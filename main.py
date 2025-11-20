import sys, os, json, time
from PySide6 import QtWidgets, QtCore, QtGui

from capture import WindowLister, capture_window_image
from ocr_backend import ocr_image_data
from translate_backend import translate_text
from textractor_worker import TextractorWorker, get_pid_from_hwnd

APP_DIR = os.path.dirname(__file__)
TRANSLATION_FILE = os.path.join(APP_DIR, "translations.json")
LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LANG_LABELS = {"auto": "Auto", "zh": "Chinese", "en": "English", "ja": "Japanese"}


class CaptureWorker(QtCore.QThread):
    frame_ready = QtCore.Signal(object)
    ocr_ready = QtCore.Signal(list)
    prefer_lang = "auto"

    def __init__(self, hwnd, interval_ms=120, ocr_every_ms=1200,
                 enable_ocr=True, parent=None):
        super().__init__(parent)
        self.hwnd = hwnd
        self.interval = max(60, int(interval_ms)) / 1000.0
        self.ocr_interval = max(500, int(ocr_every_ms)) / 1000.0
        self.enable_ocr = enable_ocr
        self._running = False

    def run(self):
        self._running = True
        last_ocr = 0.0
        while self._running:
            start = time.time()
            img = capture_window_image(self.hwnd)
            if img is not None:
                self.frame_ready.emit(img)

                if self.enable_ocr and (start - last_ocr) >= self.ocr_interval:
                    try:
                        data = ocr_image_data(img, self.prefer_lang)
                        self.ocr_ready.emit(data)
                    except Exception as e:
                        print("[OCR ERROR]", e)
                    last_ocr = start

            dt = time.time() - start
            sleep_t = self.interval - dt
            if sleep_t > 0:
                time.sleep(sleep_t)

    def stop(self):
        self._running = False
        self.wait(2000)


class PreviewWidget(QtWidgets.QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(720, 405)
        self.setScaledContents(True)
        self.qimage = None
        self.overlay_entries = []
        self.setStyleSheet("background-color: #202225; border-radius: 8px;")

    def update_frame(self, pil_img):
        data = pil_img.tobytes("raw", "RGB")
        w, h = pil_img.size
        self.qimage = QtGui.QImage(data, w, h, QtGui.QImage.Format.Format_RGB888)
        self.update()

    def update_overlay(self, entries):
        self.overlay_entries = entries
        self.update()

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)

        if self.qimage is not None:
            # Draw base image
            target = self.rect()
            pix = QtGui.QPixmap.fromImage(self.qimage)
            painter.drawPixmap(target, pix, pix.rect())

            src_w, src_h = self.qimage.width(), self.qimage.height()
            scale_x = target.width() / max(1, src_w)
            scale_y = target.height() / max(1, src_h)

            for e in self.overlay_entries:
                x, y, w, h = e["bbox"]
                tx, ty = int(x * scale_x), int(y * scale_y)

                txt = e.get("translation") or e.get("text") or ""

                # ---- Set font ----
                font = painter.font()
                font.setPointSize(13)
                painter.setFont(font)
                metrics = QtGui.QFontMetrics(font)

                # ---- Set max width for text ----
                max_width = int(target.width() * 0.6)
                text_rect = metrics.boundingRect(
                    0, 0,
                    max_width,
                    9999,
                    QtCore.Qt.TextWordWrap,
                    txt
                )

                box_w = text_rect.width() + 12
                box_h = text_rect.height() + 12

                # ---- Draw background box (auto-sized) ----
                painter.setPen(QtGui.QPen(QtGui.QColor(255, 215, 0, 230), 2))
                painter.setBrush(QtGui.QColor(0, 0, 0, 160))
                painter.drawRect(QtCore.QRect(tx, ty, box_w, box_h))

                # ---- Draw text inside ----
                text_area = QtCore.QRect(tx + 6, ty + 6, text_rect.width(), text_rect.height())
                painter.setPen(QtGui.QColor(255, 255, 0))
                painter.drawText(
                    text_area,
                    QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop | QtCore.Qt.TextWordWrap,
                    txt
                )

        painter.end()

class MainWindow(QtWidgets.QWidget):
    translate_signal = QtCore.Signal(str, str, str)

    def __init__(self):
        super().__init__()
        self.translate_signal.connect(self.translate_and_update)

        root = QtWidgets.QHBoxLayout(self)

        left = QtWidgets.QVBoxLayout()
        bar = QtWidgets.QHBoxLayout()
        self.win_list = QtWidgets.QComboBox()
        self.refresh_btn = QtWidgets.QPushButton("Refresh Windows")
        self.attach_btn = QtWidgets.QPushButton("Attach")
        bar.addWidget(self.win_list)
        bar.addWidget(self.refresh_btn)
        bar.addWidget(self.attach_btn)
        left.addLayout(bar)

        self.preview = PreviewWidget()
        left.addWidget(self.preview, 1)

        ctrl = QtWidgets.QHBoxLayout()
        self.realtime_chk = QtWidgets.QCheckBox("Real-time OCR")
        self.hook_mode_chk = QtWidgets.QCheckBox("Use Textractor hook")
        self.interval_spin = QtWidgets.QSpinBox()
        self.interval_spin.setRange(60, 2000)
        self.interval_spin.setValue(120)
        self.ocr_spin = QtWidgets.QSpinBox()
        self.ocr_spin.setRange(500, 5000)
        self.ocr_spin.setValue(1200)

        ctrl.addWidget(self.realtime_chk)
        ctrl.addWidget(self.hook_mode_chk)
        ctrl.addWidget(QtWidgets.QLabel("Frame (ms)"))
        ctrl.addWidget(self.interval_spin)
        ctrl.addWidget(QtWidgets.QLabel("OCR (ms)"))
        ctrl.addWidget(self.ocr_spin)
        left.addLayout(ctrl)

        self.status = QtWidgets.QLabel("")
        left.addWidget(self.status)

        right = QtWidgets.QVBoxLayout()
        lang_row = QtWidgets.QHBoxLayout()
        self.src_combo = QtWidgets.QComboBox()
        self.dst_combo = QtWidgets.QComboBox()
        for code in ["auto", "zh", "en", "ja"]:
            self.src_combo.addItem(LANG_LABELS[code], userData=code)
        for code in ["zh", "en", "ja"]:
            self.dst_combo.addItem(LANG_LABELS[code], userData=code)
        self.src_combo.setCurrentIndex(0)
        self.dst_combo.setCurrentIndex(1)
        lang_row.addWidget(QtWidgets.QLabel("From (OCR+Trans)"))
        lang_row.addWidget(self.src_combo)
        lang_row.addWidget(QtWidgets.QLabel("To"))
        lang_row.addWidget(self.dst_combo)
        right.addLayout(lang_row)

        self.ocr_table = QtWidgets.QTableWidget(0, 4)
        self.ocr_table.setHorizontalHeaderLabels(["Source Text", "Lang", "Translation", "BBox/Source"])
        #self.ocr_table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        #right.addWidget(self.ocr_table, 1)
        header = self.ocr_table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)  
        right.addWidget(self.ocr_table, 1)
        
        self.edit = QtWidgets.QPlainTextEdit()
        right.addWidget(self.edit)

        buttons = QtWidgets.QHBoxLayout()
        self.apply_btn = QtWidgets.QPushButton("Apply to selected")
        self.save_btn = QtWidgets.QPushButton("Save Translations")
        self.help_btn = QtWidgets.QPushButton("Help")
        buttons.addWidget(self.apply_btn)
        buttons.addWidget(self.save_btn)
        buttons.addWidget(self.help_btn)
        
        right.addLayout(buttons)

        splitL = QtWidgets.QWidget()
        splitL.setLayout(left)
        splitR = QtWidgets.QWidget()
        splitR.setLayout(right)
        splitter = QtWidgets.QSplitter()
        splitter.addWidget(splitL)
        splitter.addWidget(splitR)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter)

        self.attached_hwnd = None
        self.worker = None
        self.textractor_worker = None

        self.latest_ocr = []
        self.ocr_results = []

        self.hook_last_text = ""
        self.hook_last_translation = ""

        self.refresh_btn.clicked.connect(self.refresh_windows)
        self.attach_btn.clicked.connect(self.attach_window)
        self.realtime_chk.stateChanged.connect(self.on_realtime_changed)
        self.hook_mode_chk.stateChanged.connect(self.on_hook_mode_changed)
        self.interval_spin.valueChanged.connect(self.on_interval_changed)
        self.ocr_spin.valueChanged.connect(self.on_interval_changed)
        self.ocr_table.itemSelectionChanged.connect(self.on_select)
        self.apply_btn.clicked.connect(self.apply_translation)
        self.save_btn.clicked.connect(self.save_translations)
        self.help_btn.clicked.connect(self.help_bar)
        self.src_combo.currentIndexChanged.connect(self.on_src_lang_changed)

        self.refresh_windows()

    def refresh_windows(self):
        self.win_list.clear()
        wins = WindowLister.list_windows()
        for hwnd, title in wins:
            self.win_list.addItem(f"{title} - {hwnd}", userData=hwnd)
        self.status.setText(f"Found {len(wins)} windows")

    def attach_window(self):
        idx = self.win_list.currentIndex()
        if idx < 0:
            return
        self.attached_hwnd = self.win_list.currentData()
        self.status.setText(f"Attached to window: {self.win_list.currentText()}")

        if self.realtime_chk.isChecked():
            self.start_worker()
        if self.hook_mode_chk.isChecked():
            self.start_textractor()
            
    def help_bar(self):
        text = """
        Game Translation Tool Help:
        - Click "Refresh Windows" from the top bar to list all available windows.
        - Select a window from the dropdown and click "Attach" to connect.
        - Enable "Real-time OCR" to start capturing and OCRing the window content.
        - Enable "Use Textractor hook" to extract text using Textractor.
        - Adjust frame and OCR intervals using the spin boxes.
        - Use the language dropdowns to set source and target languages for translation.
        - Select OCR results from the table to view and edit translations.
        - Click "Apply to selected" to save edits to the selected OCR result.
        - Click "Save Translations" to save all translations to a JSON file.
        
        For more information, refer to the documentation or visit the project repository.
"""
        QtWidgets.QMessageBox.information(self, "Help", text)
    
    
    def start_worker(self):
        if not self.attached_hwnd:
            self.status.setText("No window attached.")
            return

        self.stop_worker()

        enable_ocr = self.realtime_chk.isChecked() and not self.hook_mode_chk.isChecked()

        self.worker = CaptureWorker(
            self.attached_hwnd,
            interval_ms=self.interval_spin.value(),
            ocr_every_ms=self.ocr_spin.value(),
            enable_ocr=enable_ocr,
        )
        self.worker.prefer_lang = self.src_combo.currentData()
        self.worker.frame_ready.connect(self.on_frame_ready)
        if enable_ocr:
            self.worker.ocr_ready.connect(self.on_ocr_ready)
        self.worker.start()
        self.status.setText("Real-time preview started.")

    def stop_worker(self):
        if self.worker:
            self.worker.stop()
            self.worker = None
        if self.textractor_worker:
            self.textractor_worker.stop()
            self.textractor_worker = None

    def on_realtime_changed(self, state):
        if state == QtCore.Qt.Checked:
            self.start_worker()
        else:
            self.stop_worker()
            self.status.setText("Real-time preview stopped.")

    def on_interval_changed(self, *_):
        if self.worker:
            self.start_worker()

    def start_textractor(self):
        if not self.attached_hwnd:
            self.status.setText("No window attached for Textractor.")
            return
        if self.textractor_worker:
            self.textractor_worker.stop()
            self.textractor_worker = None

        pid = get_pid_from_hwnd(self.attached_hwnd)
        if not pid:
            self.status.setText("Failed to get process ID for window.")
            return

        self.textractor_worker = TextractorWorker(pid)
        self.textractor_worker.text_ready.connect(self.on_hook_text)
        self.textractor_worker.start()
        self.status.setText(f"Textractor hook started (PID {pid}).")

    def stop_textractor(self):
        if self.textractor_worker:
            self.textractor_worker.stop()
            self.textractor_worker = None
            self.status.setText("Textractor hook stopped.")

    def on_hook_mode_changed(self, state):
        if self.worker:
            self.start_worker()

        if self.hook_mode_chk.isChecked() and self.attached_hwnd:
            self.start_textractor()
        else:
            self.stop_textractor()

    def on_hook_text(self, text: str):
        src_lang = self.src_combo.currentData()
        dst_lang = self.dst_combo.currentData()
        try:
            trans = translate_text(src_lang, dst_lang, text)
        except Exception:
            trans = text

        self.hook_last_text = text
        self.hook_last_translation = trans

        row = self.ocr_table.rowCount()
        self.ocr_table.insertRow(row)
        self.ocr_table.setItem(row, 0, QtWidgets.QTableWidgetItem(text))
        self.ocr_table.setItem(row, 1, QtWidgets.QTableWidgetItem("hook"))
        self.ocr_table.setItem(row, 2, QtWidgets.QTableWidgetItem(trans))
        self.ocr_table.setItem(row, 3, QtWidgets.QTableWidgetItem("hook"))

        self.ocr_results.append({
            "text": text,
            "bbox": (0, 0, 0, 0),
            "lang": "hook",
            "translation": trans,
        })
        self.status.setText("Hooked line received & translated.")

    def on_frame_ready(self, pil_img):
        src_lang = self.src_combo.currentData()
        dst_lang = self.dst_combo.currentData()

        overlay = []

        if self.hook_mode_chk.isChecked() and self.hook_last_translation:
            w, h = pil_img.size
            bbox = (int(w * 0.05), int(h * 0.70), int(w * 0.90), int(h * 0.22))
            overlay.append({
                "text": self.hook_last_text,
                "bbox": bbox,
                "translation": self.hook_last_translation,
            })
        else:
            for e in self.latest_ocr:
                txt = e["text"]
                try:
                    self.translate_signal.emit(src_lang, dst_lang, txt)
                    trans = self.last_translation
                except Exception:
                    trans = txt
                overlay.append({
                    "text": txt,
                    "bbox": e["bbox"],
                    "translation": trans,
                })

        self.preview.update_overlay(overlay)
        self.preview.update_frame(pil_img)

    def on_ocr_ready(self, entries):
        self.latest_ocr = entries
        self.ocr_results = []
        self.ocr_table.setRowCount(0)
        for e in entries:
            src = e["text"]
            row = self.ocr_table.rowCount()
            self.ocr_table.insertRow(row)
            self.ocr_table.setItem(row, 0, QtWidgets.QTableWidgetItem(src))
            self.ocr_table.setItem(row, 1, QtWidgets.QTableWidgetItem(e.get("lang", "unknown")))
            self.ocr_table.setItem(row, 2, QtWidgets.QTableWidgetItem(""))
            self.ocr_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(e["bbox"])))
            self.ocr_results.append({
                "text": src,
                "bbox": e["bbox"],
                "lang": e.get("lang", "unknown"),
                "translation": "",
            })

    def on_select(self):
        idxs = self.ocr_table.selectionModel().selectedRows()
        if not idxs:
            return
        r = idxs[0].row()
        self.edit.setPlainText(self.ocr_results[r].get("translation", ""))

    def apply_translation(self):
        idxs = self.ocr_table.selectionModel().selectedRows()
        if not idxs:
            self.status.setText("No selection.")
            return
        r = idxs[0].row()
        text = self.edit.toPlainText().strip()
        self.ocr_results[r]["translation"] = text
        self.ocr_table.item(r, 2).setText(text)
        self.status.setText("Applied translation to selected.")

    def save_translations(self):
        with open(TRANSLATION_FILE, "w", encoding="utf-8") as f:
            json.dump(self.ocr_results, f, ensure_ascii=False, indent=2)
        self.status.setText(f"Saved translations to {TRANSLATION_FILE}")

    def on_src_lang_changed(self, *_):
        if self.worker:
            self.start_worker()

    def closeEvent(self, e):
        self.stop_worker()
        return super().closeEvent(e)

    def translate_and_update(self, src, dst, txt):
        trans = translate_text(src, dst, txt)
        self.last_translation = trans


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
