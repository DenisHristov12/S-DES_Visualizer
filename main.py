import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

try:
    from sdes import encrypt as sdes_encrypt, decrypt as sdes_decrypt
except Exception as e:
    # If import fails, show a minimal message box later on app start
    sdes_encrypt = sdes_decrypt = None
    _import_error = e
else:
    _import_error = None

APP_TITLE = "S-DES Visualizer"


BIT_FONT = ("Consolas", 12)
UI_FONT = ("Segoe UI", 11)


def is_bitstring(s: str) -> bool:
    return all(ch in "01" for ch in s)


def validate_inputs(plaintext: str, key: str, mode: str):
    # mode in {"encrypt", "decrypt"}
    if not is_bitstring(plaintext):
        raise ValueError("Данните трябва да са само от 0 и 1.")
    if not is_bitstring(key):
        raise ValueError("Ключът трябва да е само от 0 и 1.")
    if len(plaintext) != 8:
        raise ValueError("Текстът трябва да е точно 8 бита (напр. 10111101).")
    if len(key) != 10:
        raise ValueError("Ключът трябва да е точно 10 бита (напр. 1010000010).")
    if mode not in {"encrypt", "decrypt"}:
        raise ValueError("Невалиден режим.")


class SDESApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.title(APP_TITLE)
        self.master.geometry("1000x650")
        self.master.minsize(920, 580)

        # Top-level layout: left controls, right results
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        self.build_left_panel()
        self.build_right_panel()

        if _import_error:
            messagebox.showerror(
                "Проблем с импорта",
                f"Неуспешен импорт на sdes.py. Увери се, че файлът е в същата папка.\n\nГрешка: {_import_error}",
            )

    # LEFT PANEL -------------------------------------------------------------
    def build_left_panel(self):
        left = ttk.Frame(self, padding=16)
        left.grid(row=0, column=0, sticky="nsw")

        # Title
        title = ttk.Label(left, text="Входни данни", font=("Segoe UI Semibold", 13))
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        # Plaintext / Ciphertext
        ttk.Label(left, text="Текст (8 бита):", font=UI_FONT).grid(
            row=1, column=0, sticky="w"
        )
        self.entry_text = ttk.Entry(left, width=24, font=BIT_FONT)
        self.entry_text.grid(row=2, column=0, columnspan=2, sticky="we", pady=(2, 10))
        self.entry_text.insert(0, "10111101")

        # Key
        ttk.Label(left, text="Ключ (10 бита):", font=UI_FONT).grid(
            row=3, column=0, sticky="w"
        )
        self.entry_key = ttk.Entry(left, width=24, font=BIT_FONT)
        self.entry_key.grid(row=4, column=0, columnspan=2, sticky="we", pady=(2, 18))
        self.entry_key.insert(0, "1010000010")

        # Buttons
        btn_encrypt = ttk.Button(
            left, text="Encrypt (Шифрирай)", command=self.on_encrypt
        )
        btn_decrypt = ttk.Button(
            left, text="Decrypt (Дешифрирай)", command=self.on_decrypt
        )
        btn_encrypt.grid(row=5, column=0, sticky="we", pady=(0, 8))
        btn_decrypt.grid(row=6, column=0, sticky="we", pady=(0, 16))

        # Help / format hint
        hint = (
            "Въведи точно 8 бита за текст и 10 бита за ключ.\n"
            "Пример: Текст 10111101, Ключ 1010000010."
        )
        ttk.Label(left, text=hint, font=("Segoe UI", 9)).grid(
            row=7, column=0, columnspan=2, sticky="w"
        )

    # RIGHT PANEL ------------------------------------------------------------
    def build_right_panel(self):
        right = ttk.Frame(self, padding=(8, 12, 12, 12))
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        # Output summary line
        self.result_var = tk.StringVar(value="Резултат: —")
        lbl_result = ttk.Label(
            right, textvariable=self.result_var, font=("Consolas", 13)
        )
        lbl_result.grid(row=0, column=0, sticky="we", pady=(0, 8))

        # Notebook with tabs for detailed steps
        self.nb = ttk.Notebook(right)
        self.nb.grid(row=1, column=0, sticky="nsew")

        # Tabs: Key Gen, Round 1, Switch, Round 2, Final
        self.tab_key = self._make_tab(self.nb, "Key Generation")
        self.tab_ip = self._make_tab(self.nb, "Initial Permutation (IP)")
        self.tab_r1 = self._make_tab(self.nb, "Round 1")
        self.tab_sw = self._make_tab(self.nb, "Switch")
        self.tab_r2 = self._make_tab(self.nb, "Round 2")
        self.tab_final = self._make_tab(self.nb, "Final (IP^-1)")

        self.nb.add(self.tab_key["frame"], text="Key Gen")
        self.nb.add(self.tab_ip["frame"], text="IP")
        self.nb.add(self.tab_r1["frame"], text="Round 1")
        self.nb.add(self.tab_sw["frame"], text="Switch")
        self.nb.add(self.tab_r2["frame"], text="Round 2")
        self.nb.add(self.tab_final["frame"], text="Final")

    def _make_tab(self, nb: ttk.Notebook, title: str):
        frame = ttk.Frame(nb)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        # Use a Treeview for step/value pairs
        tree = ttk.Treeview(
            frame, columns=("step", "value"), show="headings", selectmode="browse"
        )
        tree.heading("step", text="Стъпка")
        tree.heading("value", text="Стойност")
        tree.column("step", anchor="w", width=240)
        tree.column("value", anchor="w")
        tree.grid(row=0, column=0, sticky="nsew")

        # Add scrollbar
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")

        return {"frame": frame, "tree": tree}

    # Populate helpers -------------------------------------------------------
    def clear_all_tabs(self):
        for tab in (
            self.tab_key,
            self.tab_ip,
            self.tab_r1,
            self.tab_sw,
            self.tab_r2,
            self.tab_final,
        ):
            for iid in tab["tree"].get_children():
                tab["tree"].delete(iid)

    def fill_tab(self, tab, data_pairs):
        tree = tab["tree"]
        for step, value in data_pairs:
            tree.insert("", "end", values=(step, value))

    def render_log_encrypt(self, log: dict, cipher: str):
        # Key generation
        kg = log.get("Key generation", {})
        self.fill_tab(
            self.tab_key,
            [
                ("P10", kg.get("P10", "")),
                ("LS-1 (L||R)", kg.get("LS-1", "")),
                ("K1", kg.get("K1", "")),
                ("LS-2 (L||R)", kg.get("LS-2", "")),
                ("K2", kg.get("K2", "")),
            ],
        )

        # IP
        self.fill_tab(self.tab_ip, [("IP(plaintext)", log.get("IP", ""))])

        # Round 1
        r1 = log.get("Round 1", {})
        self.fill_tab(
            self.tab_r1,
            [
                ("EP(R)", r1.get("EP(R)", "")),
                ("XOR", r1.get("XOR", "")),
                ("S0_out", r1.get("S0_out", "")),
                ("S1_out", r1.get("S1_out", "")),
                ("P4", r1.get("P4", "")),
                ("L_new", r1.get("L_new", "")),
            ],
        )

        # Switch
        self.fill_tab(self.tab_sw, [("After swap", log.get("Switch", ""))])

        # Round 2
        r2 = log.get("Round 2", {})
        self.fill_tab(
            self.tab_r2,
            [
                ("EP(R)", r2.get("EP(R)", "")),
                ("XOR", r2.get("XOR", "")),
                ("S0_out", r2.get("S0_out", "")),
                ("S1_out", r2.get("S1_out", "")),
                ("P4", r2.get("P4", "")),
                ("L_new", r2.get("L_new", "")),
            ],
        )

        # Final
        self.fill_tab(self.tab_final, [("IP^-1", log.get("Cipher", cipher))])

    def render_log_decrypt(self, log: dict, plain: str):
        # Key generation
        kg = log.get("Key generation", {})
        self.fill_tab(
            self.tab_key,
            [
                ("P10", kg.get("P10", "")),
                ("LS-1 (L||R)", kg.get("LS-1", "")),
                ("K1", kg.get("K1", "")),
                ("LS-2 (L||R)", kg.get("LS-2", "")),
                ("K2", kg.get("K2", "")),
            ],
        )

        # IP
        self.fill_tab(self.tab_ip, [("IP(ciphertext)", log.get("IP", ""))])

        # Round 1 (with K2)
        r1 = log.get("Round 1", {})
        self.fill_tab(
            self.tab_r1,
            [
                ("EP(R)", r1.get("EP(R)", "")),
                ("XOR", r1.get("XOR", "")),
                ("S0_out", r1.get("S0_out", "")),
                ("S1_out", r1.get("S1_out", "")),
                ("P4", r1.get("P4", "")),
                ("L_new", r1.get("L_new", "")),
            ],
        )

        # Switch
        self.fill_tab(self.tab_sw, [("After swap", log.get("Switch", ""))])

        # Round 2 (with K1)
        r2 = log.get("Round 2", {})
        self.fill_tab(
            self.tab_r2,
            [
                ("EP(R)", r2.get("EP(R)", "")),
                ("XOR", r2.get("XOR", "")),
                ("S0_out", r2.get("S0_out", "")),
                ("S1_out", r2.get("S1_out", "")),
                ("P4", r2.get("P4", "")),
                ("L_new", r2.get("L_new", "")),
            ],
        )

        # Final
        self.fill_tab(self.tab_final, [("IP^-1", log.get("Plain", plain))])

    # Handlers ---------------------------------------------------------------
    def on_encrypt(self):
        text = self.entry_text.get().strip()
        key = self.entry_key.get().strip()
        try:
            validate_inputs(text, key, mode="encrypt")
            if sdes_encrypt is None:
                raise RuntimeError("sdes.py не е наличен или има грешка при импорта.")
            cipher, log = sdes_encrypt(text, key)
        except Exception as e:
            messagebox.showerror("Грешка", str(e))
            return

        self.result_var.set(f"Резултат (ciphertext): {cipher}")
        self.clear_all_tabs()
        self.render_log_encrypt(log, cipher)
        self.nb.select(self.tab_final["frame"])  # jump to final

    def on_decrypt(self):
        text = self.entry_text.get().strip()
        key = self.entry_key.get().strip()
        try:
            validate_inputs(text, key, mode="decrypt")
            if sdes_decrypt is None:
                raise RuntimeError("sdes.py не е наличен или има грешка при импорта.")
            plain, log = sdes_decrypt(text, key)
        except Exception as e:
            messagebox.showerror("Грешка", str(e))
            return

        self.result_var.set(f"Резултат (plaintext): {plain}")
        self.clear_all_tabs()
        self.render_log_decrypt(log, plain)
        self.nb.select(self.tab_final["frame"])  # jump to final


if __name__ == "__main__":
    root = tk.Tk()
    # Use ttk themes for nicer look
    try:
        style = ttk.Style()
        # Try clam or default
        style.theme_use("clam")
    except Exception:
        pass

    app = SDESApp(root)
    app.grid(row=0, column=0, sticky="nsew")

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    root.mainloop()
