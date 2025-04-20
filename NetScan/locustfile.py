from asyncio import Task


def on_start(self):
    response = self.client.post("/login", json={
        "username": "testuser",
        "password": "testpass"
    })

    if response.status_code == 200:
        self.token = response.json().get("token", "")
        self.headers = {"Authorization": f"Bearer {self.token}"}
    else:
        self.token = ""
        self.headers = {}

@Task(1)
def quick_scan(self):
    self.client.post("/scan/quick", json={"ip": "192.168.1.1"})

@Task(1)
def super_scan(self):
    if self.token:
        self.client.post("/scan/deep", json={"ip": "192.168.1.1"}, headers=self.headers)

@Task(1)
def fetch_report(self):
    self.client.get("/report/1", headers=self.headers)
