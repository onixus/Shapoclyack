import type { Metadata } from "next";
import localFont from "next/font/local";
import { Providers } from "@/components/providers";
import "./globals.css";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
  weight: "100 900",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "Shapoclyack",
  description: "MSSP and Enterprise Vulnerability Management dashboard",
};

const appearanceBoot = `(function(){try{var t=localStorage.getItem("shapoclyack.theme");var l=localStorage.getItem("shapoclyack.locale");var d=document.documentElement;if(t==="light"){d.classList.remove("dark");d.classList.add("light");d.style.colorScheme="light";}else{d.classList.add("dark");d.classList.remove("light");d.style.colorScheme="dark";}if(l==="ru"||l==="en")d.lang=l;}catch(e){}})();`;

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
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
