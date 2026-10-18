from pathlib import Path
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from accounts.models import Profile
from scans.models import Scan, ScanFile, VulnerabilityFinding
from scans.scanner import analyze

S = Path(__file__).resolve().parents[3] / "samples"


class Command(BaseCommand):
    help = "Create DEMO user (demo / Demo!Pass123) and demo scans (flagged is_demo)."

    def handle(self, *a, **kw):
        U = get_user_model()
        u, new = U.objects.get_or_create(username="demo", defaults={"email": "demo@example.com"})
        if new:
            u.set_password("Demo!Pass123")
            u.save()
            Profile.objects.create(user=u)
        for fn, lang in [("vulnerable.py", "python"), ("fixed.py", "python"), ("vulnerable.php", "php"), ("vulnerable.js", "javascript")]:
            code = (S / fn).read_text()
            sc = Scan.objects.create(user=u, title=f"[DEMO] {fn}", language=lang, status="completed", is_demo=True)
            sf = ScanFile.objects.create(scan=sc, filename=fn, content=code, size=len(code))
            VulnerabilityFinding.objects.bulk_create([VulnerabilityFinding(scan=sc, file=sf, **f) for f in analyze(code, lang)])
        self.stdout.write("Demo data created.")
