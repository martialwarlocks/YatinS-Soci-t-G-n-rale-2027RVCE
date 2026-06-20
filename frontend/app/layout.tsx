import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "IdentityLens AI",
  description: "Cross-Platform Identity Risk Intelligence Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
