🇹🇷 

Pass​ive Scanner, web hedefleri üzerinde pasif keşif ve bilgi toplama işlemini kolaylaştırmak amacıyla Python’la geliştirdiğim ilk ve en kapsamlı projelerimden biridir. Bu araç, bir web sitesinin dış yüzeyini analiz ederek potansiyel güvenlik yapılandırma hatalarını ve bilgi sızıntılarını tespit etmeye odaklanır.

Geliştirme sürecinde öğrendiklerim:

Çoklu iş parçacığı (threading) ile performans optimizasyonu

Socket programlama ile ağ temelleri ve port taraması

HTTP/S protokolleri üzerinden header analizi

cryptography kütüphanesi ile SSL/TLS sertifika inceleme

whois kütüphanesi ile domain sahibi ve kayıt detaylarını öğrenme

robots.txt ve dizin taraması ile gizli kaynak keşfi

HTTP OPTIONS kontrolü ile izin verilen metodları listeleme

Bu araç, siber güvenlik ve Python öğrenme yolculuğumun dönüm noktalarından biri oldu. Hem yeni başlayanlar için eğitim materyali, hem de hızlı ön analiz yapmak isteyen uzmanlar için pratik bir CLI (Command‑Line Interface) aracı olarak tasarlandı.

🇬🇧 English 

Passive Recon Scanner is one of my first and most ambitious Python projects aimed at passive reconnaissance and information gathering on web targets. By analyzing a site's public-facing surface, it quickly identifies potential misconfigurations and data leaks.

Key learnings and features during development:

Performance optimization with multi-threading

Networking fundamentals and port scanning using sockets

HTTP/S header analysis for security policy detection

Deep SSL/TLS certificate inspection using the cryptography library

Domain registration details via the whois library

Hidden paths discovery through robots.txt and directory enumeration

HTTP OPTIONS method enumeration for allowed HTTP verbs

This tool marks a milestone in my cybersecurity and Python journey. It serves both as a learning resource for beginners and a rapid CLI utility for seasoned professionals.

✨ Detaylı Özellikler / Features in Detail

🔹 Header Analizi / Header Analysis

CSP, HSTS, X-Frame-Options gibi kritik güvenlik başlıklarının varlığını ve yapılandırmasını kontrol eder.

🔹 SSL Sertifika Kontrolü / SSL Certificate Check

Sertifikanın yetkilisi, geçerlilik tarihleri, imza algoritması gibi detayları inceler.

🔹 Alt Alan Adı ve Dizin Taraması / Subdomain & Directory Scanning

Yaygın wordlist’lerle gizli veya unutulmuş alt alan adları ve dizinler keşfeder.

🔹 Robots.txt Analizi / Robots.txt Analyzer

robots.txt içindeki Disallow ve Allow kurallarına göre potansiyel gizli yolları ifşa eder.

🔹 Whois Sorgusu / Whois Lookup

Alan adının kayıt bilgileri, DNS sunucuları, kayıt/sona erme tarihleri gibi bilgileri listeler.

🔹 HTTP Metot Kontrolü / HTTP OPTIONS Check

Sunucunun hangi HTTP metodlarını kabul ettiğini belirler (GET, POST, PUT, DELETE vs.).

🛠️ Kurulum & Başlangıç / Getting Started

Ön Gereksinimler / Prerequisites

Python 3.9+

Git

Projeyi Klonlama / Cloning the Repo

git clone https://github.com/mtezcan0/passive-scanner.git
cd passive-scanner

Sanal Ortam Oluşturma / Setup Virtual Environment

python3 -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate        # Windows

Bağımlılıkları Yükleme / Install Dependencies

pip install -r requirements.txt

Çalıştırma / Run the Scanner

python scanner.py




📧 İletişim / Contact

- GitHub: [mtezcan0](https://github.com/mtezcan0)  
- E-mail: <mehmet.tezcan.tr@gmail.com>

