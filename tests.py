from pathlib import Path
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from .scanner import analyze

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
User = get_user_model()


class ScannerTests(APITestCase):
    def test_python_vulnerable_detected(self):
        found = analyze((SAMPLES / "vulnerable.py").read_text(), "python")
        cwes = {f["cwe"] for f in found}
        self.assertIn("CWE-798", cwes)
        self.assertIn("CWE-89", cwes)

    def test_fixed_python_has_no_high_findings(self):
        found = analyze((SAMPLES / "fixed.py").read_text(), "python")
        self.assertFalse([f for f in found if f["severity"] in ("High", "Critical")])

    def test_php_and_js(self):
        self.assertTrue(analyze((SAMPLES / "vulnerable.php").read_text(), "php"))
        self.assertTrue(analyze((SAMPLES / "vulnerable.js").read_text(), "javascript"))


class ApiTests(APITestCase):
    def auth(self, name):
        self.client.post("/api/auth/register/", {"username": name, "email": f"{name}@x.com", "password": "Str0ng!Pass#99"})
        t = self.client.post("/api/auth/login/", {"username": name, "password": "Str0ng!Pass#99"}).data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {t}")

    def test_isolation(self):
        self.auth("alice")
        r = self.client.post("/api/scans/", {"language": "javascript", "code": "eval(x)"}, format="json")
        self.assertEqual(r.status_code, 201)
        sid = r.data["id"]
        self.auth("bob")
        self.assertEqual(self.client.get(f"/api/scans/{sid}/").status_code, 404)

    def test_requires_auth(self):
        self.assertEqual(self.client.get("/api/scans/").status_code, 401)

    def test_bad_extension_rejected(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        self.auth("carol")
        f = SimpleUploadedFile("evil.exe", b"x")
        r = self.client.post("/api/scans/", {"language": "python", "file": f}, format="multipart")
        self.assertEqual(r.status_code, 400)

    def test_reports(self):
        self.auth("dave")
        sid = self.client.post("/api/scans/", {"language": "php", "code": "<?php eval($x);"}, format="json").data["id"]
        self.assertEqual(self.client.get(f"/api/scans/{sid}/report/?type=csv").status_code, 200)
        self.assertEqual(self.client.get(f"/api/scans/{sid}/report/?type=pdf").status_code, 200)
