import os
import requests
import pefile
import tempfile
import shutil
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import messagebox, filedialog

IIDK = "iiDk-the-actual"
MENU = "iis.Stupid.Menu"

DEFAULT_PATHS = [
    r"C:\Program Files (x86)\Steam\steamapps\common\Gorilla Tag\BepInEx\plugins",
    r"C:\Program Files (x86)\Oculus\Software\Software\another-axiom-gorilla-tag\BepInEx\plugins",
]


def get_releases():
    releases = []
    per_page = 100
    page = 1
    while True:
        url = f"https://api.github.com/repos/{IIDK}/{MENU}/releases"
        params = {"per_page": per_page, "page": page}
        r = requests.get(url, params=params)
        r.raise_for_status()
        data = r.json()
        if not data:
            break
        releases.extend(data)
        page += 1
    releases.sort(key=lambda r: r.get("published_at") or r.get("created_at") or "", reverse=True)
    return releases


def download_dll(asset_url, dest=None):
    r = requests.get(asset_url, stream=True)
    r.raise_for_status()
    if dest:
        path = dest
        with open(path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    else:
        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return path


def get_dll_info(path):
    pe = None
    try:
        pe = pefile.PE(path)
        info = {}
        if hasattr(pe, "FileInfo"):
            for fileinfo in pe.FileInfo:
                entries = fileinfo if isinstance(fileinfo, list) else [fileinfo]
                for entry in entries:
                    if hasattr(entry, "Key") and entry.Key.decode(errors="ignore") == "StringFileInfo":
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                info[key.decode(errors="ignore")] = value.decode(errors="ignore")
        return info
    except Exception:
        return {}
    finally:
        try:
            if pe:
                pe.close()
        except Exception:
            pass


class ModUpdaterApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("ii's Stupid Menu Updater")
        self.geometry("600x470")

        ttk.Label(self, text="ii's Stupid Menu Updater", font=("Segoe UI", 16, "bold")).pack(pady=10)

        path_frame = ttk.Frame(self)
        path_frame.pack(pady=5, fill="x", padx=20)
        ttk.Label(path_frame, text="Gorilla Tag Path:").pack(anchor="w")
        self.game_path_var = tk.StringVar()
        self.path_entry = ttk.Entry(path_frame, textvariable=self.game_path_var, width=50)
        self.path_entry.pack(side="left", padx=(0,5))
        ttk.Button(path_frame, text="Browse", command=self.browse_game_path).pack(side="left")

        self.label_latest = ttk.Label(self, text="Latest Release: Checking...", font=("Segoe UI", 12))
        self.label_latest.pack(pady=10)

        self.label_installed = ttk.Label(self, text="Installed Version: Checking...", font=("Segoe UI", 12))
        self.label_installed.pack(pady=10)

        self.status_label = ttk.Label(self, text="Status: Checking...", font=("Segoe UI", 14, "bold"))
        self.status_label.pack(pady=20)

        self.version_var = tk.StringVar()
        self.version_dropdown = ttk.Combobox(self, textvariable=self.version_var, state="readonly", width=40)
        self.version_dropdown.pack(pady=10)

        self.install_button = ttk.Button(self, text="Install Selected Version", command=self.install_selected, state="disabled", bootstyle="info")
        self.install_button.pack(pady=5)

        self.update_button = ttk.Button(self, text="Update to Latest", command=self.update_mod, state="disabled", bootstyle="warning")
        self.update_button.pack(pady=5)

        self.quit_button = ttk.Button(self, text="Quit", command=self.destroy, bootstyle="secondary")
        self.quit_button.pack(pady=15)

        self.releases = []
        self.dll_assets = {}
        self.latest_version = None
        self.local_version = None

        for default_path in DEFAULT_PATHS:
            plugins = default_path
            if os.path.isdir(plugins):
                self.game_path_var.set(os.path.dirname(os.path.dirname(plugins))) 
                break

        self.after(100, self.check_versions)

    def browse_game_path(self):
        path = filedialog.askdirectory(title="Select Gorilla Tag Folder")
        if path:
            self.game_path_var.set(path)
            self.check_versions()

    @property
    def plugin_dir(self):
        path = self.game_path_var.get()
        if path and os.path.isdir(path):
            plugins = os.path.join(path, "BepInEx", "plugins")
            if os.path.isdir(plugins):
                return plugins
        return None

    def check_versions(self):
        if not self.plugin_dir:
            self.install_button.config(state="disabled")
            self.update_button.config(state="disabled")
            self.status_label.config(text="Set valid game path with BepInEx/plugins", foreground="red")
        try:
            self.releases = get_releases()
            version_list = []
            self.dll_assets.clear()
            for release in self.releases:
                for asset in release.get("assets", []):
                    if asset.get("name", "").endswith(".dll"):
                        tag = release.get("tag_name", "")
                        if tag and tag not in self.dll_assets:
                            version_list.append(tag)
                            self.dll_assets[tag] = asset
                        break

            if not version_list:
                self.status_label.config(text="No DLLs found in releases", foreground="red")
                return

            self.version_dropdown["values"] = version_list
            self.version_dropdown.current(0)
            if self.plugin_dir:
                self.install_button.config(state="normal")

            latest_tag = version_list[0]
            dll_asset = self.dll_assets[latest_tag]
            latest_dll = download_dll(dll_asset["browser_download_url"])
            latest_info = get_dll_info(latest_dll)
            self.latest_version = latest_info.get("ProductVersion", "Unknown")
            os.remove(latest_dll)
            self.label_latest.config(text=f"Latest Release: {self.latest_version} ({latest_tag})")

            plugins_folder = self.plugin_dir
            if plugins_folder:
                local_dll_path = os.path.join(plugins_folder, dll_asset["name"])
                if os.path.exists(local_dll_path):
                    local_info = get_dll_info(local_dll_path)
                    self.local_version = local_info.get("ProductVersion", "Unknown")
                    self.label_installed.config(text=f"Installed Version: {self.local_version}")
                    if self.local_version == self.latest_version:
                        self.status_label.config(text="Up to Date", foreground="green")
                        self.update_button.config(state="disabled")
                    else:
                        self.status_label.config(text="⚠ Update Available", foreground="orange")
                        self.update_button.config(state="normal")
                else:
                    self.label_installed.config(text="Installed Version: Not Found")
                    self.status_label.config(text="Not Installed", foreground="red")
                    self.update_button.config(state="normal")
            else:
                self.label_installed.config(text="Installed Version: Unknown")

        except Exception as e:
            self.status_label.config(text=f"Error: {e}", foreground="red")
            self.install_button.config(state="disabled")
            self.update_button.config(state="disabled")

    def update_mod(self):
        plugins_folder = self.plugin_dir
        if not plugins_folder:
            messagebox.showerror("Error", "Valid game path not set. Cannot install.")
            return
        latest_tag = self.version_dropdown["values"][0]
        asset = self.dll_assets[latest_tag]
        self.install_asset(asset, f"Updated mod to {latest_tag}", plugins_folder)

    def install_selected(self):
        plugins_folder = self.plugin_dir
        if not plugins_folder:
            messagebox.showerror("Error", "Valid game path not set. Cannot install.")
            return
        selected_tag = self.version_var.get()
        if not selected_tag:
            messagebox.showwarning("No Version Selected", "Please select a version first.")
            return
        asset = self.dll_assets[selected_tag]
        self.install_asset(asset, f"Installed version {selected_tag}", plugins_folder)

    def install_asset(self, asset, success_message, plugins_folder):
        try:
            local_dll_path = os.path.join(plugins_folder, asset["name"])
            temp_dll = download_dll(asset["browser_download_url"])
            shutil.copy2(temp_dll, local_dll_path)
            os.remove(temp_dll)
            messagebox.showinfo("Success", success_message)
            self.update_button.config(state="disabled")
            self.check_versions()
        except Exception as e:
            messagebox.showerror("Install Failed", str(e))


if __name__ == "__main__":
    app = ModUpdaterApp()
    app.mainloop()
