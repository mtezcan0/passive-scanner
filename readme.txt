# Passive Scanner

## English

This is one of my first coding projects — a Passive Scanner tool written in Python.  
The tool performs basic passive security checks on a given website URL, including:

- HTTP header analysis  
- SSL certificate validity check  
- Subdomain enumeration using a wordlist  
- Directory scanning using a wordlist  
- Robots.txt file fetching and parsing  
- Whois lookup for domain information  
- HTTP OPTIONS method check  

The project helped me learn threading, networking, requests handling, and working with external libraries such as `cryptography` and `whois`.  
I am continuously improving the code and plan to add a unified menu interface to make it easier to use.

Feel free to explore, test, and give feedback!

---

## Türkçe

Bu proje, kodlama kariyerimin ilk adımlarından biri olan Python ile yazılmış bir Passive Scanner aracıdır.  
Verilen bir web sitesi URL’si üzerinde şu pasif güvenlik testlerini yapar:

- HTTP başlık (header) analizi  
- SSL sertifikasının geçerlilik kontrolü  
- Kelime listesi kullanarak alt alan adı (subdomain) taraması  
- Kelime listesi kullanarak dizin (directory) taraması  
- Robots.txt dosyasını çekme ve analiz etme  
- Domain bilgisi için Whois sorgulaması  
- HTTP OPTIONS metodu kontrolü  

Bu proje sayesinde threading (çoklu iş parçacığı), ağ programlama, HTTP istekleri ve `cryptography`, `whois` gibi dış kütüphanelerle çalışma konusunda deneyim kazandım.  
Kodları geliştirmeye devam ediyorum ve tüm fonksiyonları tek bir menü altında toplamak istiyorum.

Projeyi inceleyebilir, deneyebilir ve geri bildirimde bulunabilirsiniz!

---

## Requirements / Gereksinimler

- Python 3.x  
- requests  
- cryptography  
- python-whois  

Install with:  
```bash
pip install requests cryptography python-whois
