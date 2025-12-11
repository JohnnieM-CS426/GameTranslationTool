"""
Main application for the GameTranslationTool with Luna hook support.

This module provides a Qt GUI that allows the user to attach to a
running visual novel window, perform OCR on the live game screen,
translate the extracted text, and display the results.  It also
provides an injection mode powered by LunaTranslate's native hook.
"""

from __future__ import annotations

import os
import sys
import json
import time
from typing import List, Dict, Any, Optional

from PySide6 import QtWidgets, QtCore, QtGui

from capture import WindowLister, capture_window_image
from ocr_backend import ocr_image_data
from translate_backend import translate_text, LANG_MAP
from luna_worker import LunaWorker
from textractor_worker import get_pid_from_hwnd  # reuse PID lookup


APP_DIR = os.path.dirname(__file__)
TRANSLATION_FILE = os.path.join(APP_DIR, "translations.json")
LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


class CaptureWorker(QtCore.QThread):
    """
    Background thread that captures screen frames and runs OCR periodically.
    It separates the heavy image processing from the UI thread to prevent freezing.
    """

    frame_ready = QtCore.Signal(object) # Emits the raw image for preview.
    ocr_ready = QtCore.Signal(list)     # Emits the list of text found by OCR.
    prefer_lang: str = "auto"

    def __init__(self, hwnd: int, interval_ms: int = 120, ocr_every_ms: int = 1200,
                 enable_ocr: bool = True, parent: Optional[QtCore.QObject] = None) -> None:
        """
        Configures the capture timings.
        'interval_ms' is how often we capture the screen (FPS). 'ocr_every_ms' is how often we scan text.
        """
        super().__init__(parent)
        self.hwnd = hwnd
        self.interval = max(5, int(interval_ms)) / 1000.0
        self.ocr_interval = max(100, int(ocr_every_ms)) / 1000.0
        self.enable_ocr = enable_ocr
        self._running = False

    def run(self) -> None:
        """
        The main loop. captures image -> emits image -> checks if enough time passed -> runs OCR.
        """
        self._running = True
        last_ocr = 0.0
        while self._running:
            start = time.time()
            img = capture_window_image(self.hwnd)
            if img is not None:
                self.frame_ready.emit(img)
                # Principle: Throttle OCR because it is CPU intensive. We don't need to OCR every frame.
                if self.enable_ocr and (start - last_ocr) >= self.ocr_interval:
                    try:
                        data = ocr_image_data(img, self.prefer_lang)
                        self.ocr_ready.emit(data)
                    except Exception as e:
                        print("[OCR ERROR]", e)
                    last_ocr = start
            # Sleep for the remainder of the frame interval to maintain stable FPS.
            dt = time.time() - start
            sleep_t = self.interval - dt
            if sleep_t > 0:
                time.sleep(sleep_t)

    def stop(self) -> None:
        """Stops the thread safely."""
        self._running = False
        self.wait(2000)


class PreviewWidget(QtWidgets.QWidget):
    """
    A custom widget that renders the captured game frame and draws translated text on top.
    It overrides paintEvent to handle custom graphics drawing.
    """

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.qimage: Optional[QtGui.QImage] = None
        self.overlay_entries: List[Dict[str, Any]] = []
        self.selected_bbox: Optional[tuple[int, int, int, int]] = None
        self.text_overlay_color = QtGui.QColor(255, 255, 0)
        self.setMinimumSize(480, 270)
        self.setStyleSheet("background-color: #202225; border-radius: 8px;")

    def sizeHint(self) -> QtCore.QSize:
        return QtCore.QSize(640, 360)

    def update_frame(self, pil_img) -> None:
        """
        Receives a PIL image, converts it to QImage, and triggers a repaint.
        Qt cannot display PIL images directly, so raw byte conversion is necessary.
        """
        if pil_img is None:
            return
        pil_img = pil_img.convert("RGB")
        w, h = pil_img.size
        data = pil_img.tobytes("raw", "RGB")
        # Format_RGB888 ensures correct color mapping from the raw bytes.
        self.qimage = QtGui.QImage(data, w, h, QtGui.QImage.Format.Format_RGB888)
        self.update()

    def update_overlay(self, entries: List[Dict[str, Any]]) -> None:
        """Updates the list of text blocks to draw over the image."""
        self.overlay_entries = entries or []
        self.update()

    def setTextColor(self, color: QtGui.QColor) -> None:
        self.text_overlay_color = color
        self.update()

    def set_selected_bbox(self, bbox: Optional[tuple[int, int, int, int]]) -> None:
        self.selected_bbox = bbox
        self.update()

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:
        """
        The core rendering logic.
        1. Draws the game screenshot.
        2. Calculates scaling ratios (UI size vs Image size).
        3. Draws semi-transparent boxes and translated text over the original text.
        """
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)

        # Draw base image or fill background
        if self.qimage is not None and not self.qimage.isNull():
            target_rect = self.rect()
            src_rect = self.qimage.rect()
            painter.drawImage(target_rect, self.qimage, src_rect)
        else:
            painter.fillRect(self.rect(), QtGui.QColor(32, 34, 37))

        # Highlight selected bbox (user selection from table)
        if self.selected_bbox:
            x, y, w, h = self.selected_bbox
            painter.setPen(QtGui.QPen(QtGui.QColor(0, 255, 0), 2))
            painter.drawRect(x, y, w, h)

        # Draw overlay text
        if not self.overlay_entries or self.qimage is None:
            painter.end()
            return

        src_w, src_h = self.qimage.width(), self.qimage.height()
        tgt_rect = self.rect()
        # Principle: Calculate scale factor to map image coordinates to widget coordinates.
        scale_x = tgt_rect.width() / max(1, src_w)
        scale_y = tgt_rect.height() / max(1, src_h)

        painter.setPen(self.text_overlay_color)
        font = painter.font()
        font.setPointSize(max(font.pointSize(), 10))
        painter.setFont(font)
        metrics = QtGui.QFontMetrics(font)

        for e in self.overlay_entries:
            bbox = e.get("bbox")
            text = e.get("translation") or e.get("text") or ""
            if not bbox or not text:
                continue
            x, y, w, h = bbox
            # Transform to target coordinates
            tx = int(x * scale_x)
            ty = int(y * scale_y)
            # Constrain width to 60% of the widget to avoid huge boxes
            max_w = int(tgt_rect.width() * 0.6)
            rect = metrics.boundingRect(0, 0, max_w, 1000,
                                        QtCore.Qt.AlignLeft | QtCore.Qt.TextWordWrap,
                                        text)
            box_w = rect.width() + 12
            box_h = rect.height() + 12
            # Draw semi‑transparent background for readability
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(QtGui.QColor(0, 0, 0, 160))
            painter.drawRect(QtCore.QRect(tx, ty, box_w, box_h))
            # Draw text
            painter.setPen(self.text_overlay_color)
            painter.drawText(
                QtCore.QRect(tx + 6, ty + 6, rect.width(), rect.height()),
                QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop | QtCore.Qt.TextWordWrap,
                text,
            )

        painter.end()


class MainWindow(QtWidgets.QWidget):
    """
    The main application window handling UI layout and logic.
    Manages tabs (OCR vs Injection), worker threads, and user interactions.
    """

    translate_signal = QtCore.Signal(str, str, str)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Game Translation Tool")
        self.resize(1200, 700)

        self.translate_signal.connect(self.translate_and_update)

        # Persistent state
        self.worker: Optional[CaptureWorker] = None
        self.hook_worker: Optional[LunaWorker] = None
        self.attached_hwnd: Optional[int] = None
        self.ocr_results: List[Dict[str, Any]] = []
        self.latest_ocr: List[Dict[str, Any]] = []
        self.selected_bbox: Optional[tuple[int, int, int, int]] = None

        # Layouts
        root = QtWidgets.QHBoxLayout(self)
        left_col = QtWidgets.QVBoxLayout()
        right_col = QtWidgets.QVBoxLayout()
        root.addLayout(left_col, 1)
        root.addLayout(right_col, 1)

        # Top bar with window selector and attach button
        bar = QtWidgets.QHBoxLayout()
        self.win_list = QtWidgets.QComboBox()
        self.refresh_btn = QtWidgets.QPushButton("Refresh Windows")
        self.attach_btn = QtWidgets.QPushButton("Attach")
        bar.addWidget(self.win_list)
        bar.addWidget(self.refresh_btn)
        bar.addWidget(self.attach_btn)
        left_col.addLayout(bar)

        # Tab widget for OCR and Injection
        self.tabs = QtWidgets.QTabWidget()
        self.ocr_tab = QtWidgets.QWidget()
        self.inj_tab = QtWidgets.QWidget()
        self.tabs.addTab(self.ocr_tab, "OCR")
        self.tabs.addTab(self.inj_tab, "Injection")
        left_col.addWidget(self.tabs, 1)

        # OCR tab content
        ocr_layout = QtWidgets.QVBoxLayout(self.ocr_tab)
        self.preview = PreviewWidget()
        ocr_layout.addWidget(self.preview, 1)
        # Controls for OCR frequency
        ctrl = QtWidgets.QHBoxLayout()
        self.interval_spin = QtWidgets.QSpinBox()
        self.interval_spin.setRange(5, 2000)
        self.interval_spin.setValue(50)
        self.ocr_spin = QtWidgets.QSpinBox()
        self.ocr_spin.setRange(100, 5000)
        self.ocr_spin.setValue(300)
        ctrl.addWidget(QtWidgets.QLabel("Frame (ms)"))
        ctrl.addWidget(self.interval_spin)
        ctrl.addSpacing(20)
        ctrl.addWidget(QtWidgets.QLabel("OCR (ms)"))
        ctrl.addWidget(self.ocr_spin)
        ctrl.addStretch(1)
        ocr_layout.addLayout(ctrl)

        # Injection tab content
        inj_layout = QtWidgets.QVBoxLayout(self.inj_tab)
        self.inject_log = QtWidgets.QPlainTextEdit()
        self.inject_log.setReadOnly(True)
        self.inject_log.setPlaceholderText(
            "Injection log. When attached, hooked text and translations will appear here."
        )
        mono_font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.inject_log.setFont(mono_font)
        inj_layout.addWidget(self.inject_log, 1)

        # Status label
        self.status = QtWidgets.QLabel("Ready.")
        left_col.addWidget(self.status)

        # Right column: language selection and table
        # Language row
        lang_row = QtWidgets.QHBoxLayout()
        self.src_combo = QtWidgets.QComboBox()
        self.dst_combo = QtWidgets.QComboBox()
        # Populate language combos
        # Source includes auto
        self.src_combo.addItem("Auto", userData="auto")
        for code, label in LANG_MAP.items():
            self.src_combo.addItem(label, userData=code)
        for code, label in LANG_MAP.items():
            self.dst_combo.addItem(label, userData=code)
        # Default from auto -> English
        src_index = self.src_combo.findData("auto")
        if src_index >= 0:
            self.src_combo.setCurrentIndex(src_index)
        dst_index = self.dst_combo.findData("en")
        if dst_index >= 0:
            self.dst_combo.setCurrentIndex(dst_index)
        lang_row.addWidget(QtWidgets.QLabel("From"))
        lang_row.addWidget(self.src_combo)
        lang_row.addWidget(QtWidgets.QLabel("To"))
        lang_row.addWidget(self.dst_combo)
        self.text_color_btn = QtWidgets.QPushButton("Text Color")
        lang_row.addWidget(self.text_color_btn)
        right_col.addLayout(lang_row)

        # Results table
        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            "Source Text",
            "Translate",
            "Translation",
            "BBox/Source",
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        self.table.cellClicked.connect(self.on_row_selected)
        self.table.itemSelectionChanged.connect(self.on_select)
        right_col.addWidget(self.table, 1)

        # Editor for manual translation edits
        self.edit = QtWidgets.QPlainTextEdit()
        right_col.addWidget(self.edit)

        # Buttons row
        btn_row = QtWidgets.QHBoxLayout()
        self.apply_btn = QtWidgets.QPushButton("Apply to selected")
        self.save_btn = QtWidgets.QPushButton("Save Translations")
        self.help_btn = QtWidgets.QPushButton("Help")
        btn_row.addWidget(self.apply_btn)
        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(self.help_btn)
        right_col.addLayout(btn_row)

        # Wire up signals
        self.text_color_btn.clicked.connect(self.choose_text_overlay_color)
        self.refresh_btn.clicked.connect(self.refresh_windows)
        self.attach_btn.clicked.connect(self.attach_window)
        self.interval_spin.valueChanged.connect(self.on_interval_changed)
        self.ocr_spin.valueChanged.connect(self.on_interval_changed)
        self.apply_btn.clicked.connect(self.apply_translation)
        self.save_btn.clicked.connect(self.save_translations)
        self.help_btn.clicked.connect(self.show_help)
        self.src_combo.currentIndexChanged.connect(self.on_src_lang_changed)

        # Initialize window list
        self.refresh_windows()

    # ---------------------- Window and attach logic ----------------------
    def refresh_windows(self) -> None:
        """
        Refreshes the drop-down list of available windows.
        Calls the WindowLister helper to get current open applications.
        """
        self.win_list.clear()
        try:
            wins = WindowLister.list_windows()
        except Exception as e:
            self.status.setText(f"Failed to list windows: {e}")
            return
        for hwnd, title in wins:
            if not title:
                continue
            self.win_list.addItem(title, userData=hwnd)
        self.status.setText(f"Found {self.win_list.count()} windows.")

    def current_hwnd(self) -> Optional[int]:
        """Returns the Handle (HWND) of the currently selected window in the dropdown."""
        idx = self.win_list.currentIndex()
        if idx < 0:
            return None
        return self.win_list.currentData()

    def attach_window(self) -> None:
        """
        Attaches the tool to the selected window.
        Logic splits here: Starts OCR capture if on the OCR tab, or starts memory hooking if on Injection tab.
        """
        hwnd = self.current_hwnd()
        if hwnd is None:
            self.status.setText("No window selected.")
            return
        self.attached_hwnd = hwnd
        current_title = self.win_list.currentText()
        # Determine which tab we're on
        if self.tabs.currentIndex() == 0:
            # OCR tab
            self.start_capture()
            self.stop_hook()
            self.status.setText(f"Attached OCR to window: {current_title}")
        else:
            # Injection tab
            self.start_hook()
            self.stop_capture()
            self.status.setText(f"Attached hook to window: {current_title}")

    # ---------------------- Capture / OCR handling ----------------------
    def start_capture(self) -> None:
        """Starts the visual capture thread (screen grabbing + OCR)."""
        if not self.attached_hwnd:
            return
        # Stop existing worker
        self.stop_capture()
        self.worker = CaptureWorker(
            self.attached_hwnd,
            interval_ms=self.interval_spin.value(),
            ocr_every_ms=self.ocr_spin.value(),
            enable_ocr=True,
        )
        self.worker.prefer_lang = self.src_combo.currentData()
        self.worker.frame_ready.connect(self.on_frame_ready)
        self.worker.ocr_ready.connect(self.on_ocr_ready)
        self.worker.start()

    def stop_capture(self) -> None:
        """Terminates the capture thread."""
        if self.worker:
            try:
                self.worker.stop()
            except Exception:
                pass
            self.worker = None

    def on_frame_ready(self, pil_img) -> None:
        """
        Slot called every time a new frame is captured.
        It pairs the latest OCR data with the new image to update the UI overlay.
        """
        # Build overlay from latest OCR results using cached translations
        overlay = []
        src_lang = self.src_combo.currentData()
        dst_lang = self.dst_combo.currentData()
        for e in self.latest_ocr:
            txt = e.get("text")
            try:
                # Use translate_signal so we can cache the translation
                self.translate_signal.emit(src_lang, dst_lang, txt)
                trans = self.last_translation
            except Exception:
                trans = txt
            overlay.append({"text": txt, "bbox": e.get("bbox"), "translation": trans})
        self.preview.update_overlay(overlay)
        self.preview.update_frame(pil_img)

    def on_ocr_ready(self, entries: List[Dict[str, Any]]) -> None:
        """
        Slot called when the OCR worker finishes processing a frame.
        It repopulates the data table with the new text found.
        """
        # When OCR produces new entries, update the table and results
        self.latest_ocr = entries
        self.ocr_results = []
        self.table.setRowCount(0)
        for e in entries:
            src_text = e.get("text", "")
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(src_text))
            # Create a translate button for manual translation
            btn = QtWidgets.QPushButton("Translate")
            btn.clicked.connect(lambda checked=False, r=row: self.manual_translate_row(r))
            self.table.setCellWidget(row, 1, btn)
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(""))
            bbox_str = str(e.get("bbox", ""))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(bbox_str))
            self.ocr_results.append({
                "text": src_text,
                "bbox": e.get("bbox"),
                "lang": e.get("lang", "unknown"),
                "translation": "",
            })

    # ---------------------- Hook handling ----------------------
    def start_hook(self) -> None:
        """Starts the memory hook thread (LunaWorker)."""
        if not self.attached_hwnd:
            return
        # Stop existing hook worker
        self.stop_hook()
        self.hook_worker = LunaWorker(self.attached_hwnd)
        self.hook_worker.text_ready.connect(self.on_hook_text)
        self.hook_worker.start()

    def stop_hook(self) -> None:
        """Terminates the memory hook thread."""
        if self.hook_worker:
            try:
                self.hook_worker.stop()
            except Exception:
                pass
            self.hook_worker = None

    def on_hook_text(self, text: str) -> None:
        """
        Slot called when the memory hook retrieves text from the game engine.
        It translates the text and logs it to the Injection tab.
        """
        # Called when hook captures new text
        src_lang = self.src_combo.currentData()
        dst_lang = self.dst_combo.currentData()
        try:
            trans = translate_text(src_lang, dst_lang, text)
        except Exception:
            trans = text
        # Append to injection log
        timestamp = time.strftime("%H:%M:%S")
        self.inject_log.appendPlainText(f"[{timestamp}] {text}\n -> {trans}\n")
        # Add to table
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(text))
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem("hook"))
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(trans))
        self.table.setItem(row, 3, QtWidgets.QTableWidgetItem("hook"))
        self.ocr_results.append({
            "text": text,
            "bbox": (0, 0, 0, 0),
            "lang": "hook",
            "translation": trans,
        })

    # ---------------------- Misc UI handlers ----------------------
    def on_interval_changed(self) -> None:
        """Restarts capture if the user changes frame rate settings."""
        # Restart the capture worker with new intervals if running
        if self.worker:
            self.start_capture()

    def on_row_selected(self, row: int, col: int) -> None:
        """Highlights the corresponding bounding box in the preview when a table row is clicked."""
        # Highlight the selected bbox on preview
        if row < 0 or row >= len(self.ocr_results):
            return
        bbox = self.ocr_results[row].get("bbox")
        self.selected_bbox = bbox
        self.preview.set_selected_bbox(bbox)

    def on_select(self) -> None:
        """Fills the edit box with the current translation when a row is selected."""
        # Load translation into edit box when row selected
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            return
        r = idxs[0].row()
        text = self.ocr_results[r].get("translation", "")
        self.edit.setPlainText(text)

    def manual_translate_row(self, row: int) -> None:
        """Triggers a translation for a specific row via the button."""
        item = self.table.item(row, 0)
        if not item:
            return
        src_text = item.text()
        src_lang = self.src_combo.currentData()
        dst_lang = self.dst_combo.currentData()
        try:
            trans = translate_text(src_lang, dst_lang, src_text)
        except Exception:
            trans = src_text
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(trans))
        if 0 <= row < len(self.ocr_results):
            self.ocr_results[row]["translation"] = trans

    def translate_and_update(self, src: str, dst: str, text: str) -> None:
        """
        Helper method connected to a signal to handle translations.
        Ensures translations happen on the main thread or are safely cached.
        """
        # Called via signal from on_frame_ready
        trans = translate_text(src, dst, text)
        self.last_translation = trans

    def apply_translation(self) -> None:
        """Saves the text from the edit box back into the table and results list."""
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            self.status.setText("No selection.")
            return
        r = idxs[0].row()
        text = self.edit.toPlainText().strip()
        self.table.setItem(r, 2, QtWidgets.QTableWidgetItem(text))
        if 0 <= r < len(self.ocr_results):
            self.ocr_results[r]["translation"] = text
        self.status.setText("Applied translation to selected.")

    def save_translations(self) -> None:
        """Exports the current results to a JSON file."""
        try:
            with open(TRANSLATION_FILE, "w", encoding="utf-8") as f:
                json.dump(self.ocr_results, f, ensure_ascii=False, indent=2)
            self.status.setText(f"Saved translations to {TRANSLATION_FILE}")
        except Exception as e:
            self.status.setText(f"Failed to save translations: {e}")

    def choose_text_overlay_color(self) -> None:
        """Opens a color picker dialog to change the overlay text color."""
        color = QtWidgets.QColorDialog.getColor(
            self.preview.text_overlay_color, self, "Choose overlay text color"
        )
        if color.isValid():
            self.preview.setTextColor(color)

    def on_src_lang_changed(self) -> None:
        """Updates the preferred language for the OCR engine when the combo box changes."""
        # Update OCR preferred language
        if self.worker:
            self.worker.prefer_lang = self.src_combo.currentData()

    def show_help(self) -> None:
        """Displays a help dialog with instructions."""
        msg = (
            "<b>Game Translation Tool (OCR & Luna Hook)</b><br><br>"
            "<b>Workflow:</b><br>"
            "1. Use <i>Refresh Windows</i> to populate the list of open windows.<br>"
            "2. Select a game window.<br>"
            "3. Choose either the OCR or Injection tab.<br>"
            "   - In OCR mode: Click <i>Attach</i> to start live capture, OCR and overlay translation.<br>"
            "   - In Injection mode: Click <i>Attach</i> to start the Luna hook.  You must have"
            "     placed Luna's DLLs and injected the hook into the process separately.<br>"
            "4. Use the language selectors to choose source and target languages.<br>"
            "5. Click table rows to edit translations manually, then click <i>Apply</i> and"
            "   <i>Save</i> to persist them.<br>"
            "<br>"
            "Note: The injection mode depends on native binaries that are not included in this"
            " repository.  Without them the hook will produce no output."
        )
        QtWidgets.QMessageBox.information(self, "Help", msg)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        """Handles application closure, ensuring all threads are stopped gracefully."""
        # Clean up threads on exit
        self.stop_capture()
        self.stop_hook()
        super().closeEvent(event)



def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()