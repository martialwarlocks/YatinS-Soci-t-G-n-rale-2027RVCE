const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("token");
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) {
    (headers as Record<string, string>)["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (res.status === 401) {
    if (typeof window !== "undefined") {
      localStorage.removeItem("token");
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

export async function login(username: string, password: string) {
  const res = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  return res.json();
}

export function riskColor(score: number): string {
  if (score >= 80) return "risk-critical";
  if (score >= 60) return "risk-high";
  if (score >= 40) return "risk-medium";
  return "risk-low";
}

export function riskBg(score: number): string {
  if (score >= 80) return "bg-red-500/20 border-red-500/40";
  if (score >= 60) return "bg-orange-500/20 border-orange-500/40";
  if (score >= 40) return "bg-yellow-500/20 border-yellow-500/40";
  return "bg-green-500/20 border-green-500/40";
}
