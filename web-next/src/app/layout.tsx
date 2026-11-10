import type { Metadata } from "next";
import localFont from "next/font/local";
import { Providers } from "@/components/providers";
import "./globals.css";

// Inter and JetBrains Mono are SIL Open Font License 1.1. The files are
// served from this build so a closed network never calls a font CDN.
const inter = localFont({
  src: "./fonts/InterVariable.woff2",
  variable: "--font-inter",
  weight: "100 900",
  display: "swap",
});
const jetbrains = localFont({
  src: "./fonts/JetBrainsMonoVariable.woff2",
  variable: "--font-jetbrains",
  weight: "100 900",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Shapoclyack",
  description: "MSSP and Enterprise Vulnerability Management dashboard",
};

const appearanceBoot = `(function(){try{var d=document.documentElement;var next=localStorage.getItem("apex.theme");var legacy=localStorage.getItem("shapoclyack.theme");var pref=(next==="dark"||next==="light"||next==="system")?next:(legacy==="light"||legacy==="dark")?legacy:"dark";if(next!=="dark"&&next!=="light"&&next!=="system"&&(legacy==="light"||legacy==="dark")){localStorage.setItem("apex.theme",pref);}var resolved=pref;if(pref==="system"){resolved=window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";}d.classList.toggle("dark",resolved==="dark");d.classList.toggle("light",resolved==="light");d.dataset.theme=resolved;d.style.colorScheme=resolved;var l=localStorage.getItem("shapoclyack.locale");if(l==="ru"||l==="en")d.lang=l;}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: appearanceBoot }} />
      </head>
      <body className={`${inter.variable} ${jetbrains.variable} antialiased`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
