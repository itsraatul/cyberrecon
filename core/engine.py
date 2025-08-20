import importlib

class ReconEngine:
    def __init__(self, target):
        self.target = target
        self.modules = []

    def load_module(self, module_name):
        try:
            mod = importlib.import_module(f"modules.{module_name}")
            self.modules.append(mod)
            print(f"[+] Loaded module: {module_name}")
        except ImportError as e:
            print(f"[!] Could not load module {module_name}: {e}")

    def run(self):
        print(f"\n[*] Running CyberRecon on {self.target}...\n")
        for mod in self.modules:
            try:
                mod.run(self.target)
            except Exception as e:
                print(f"[!] Error running module {mod.__name__}: {e}")
