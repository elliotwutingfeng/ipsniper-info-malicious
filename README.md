# ipsniper.info malicious blocklist

![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![AIOHTTP](https://img.shields.io/badge/AIOHTTP-2C5BB4?style=for-the-badge&logo=aiohttp&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

[![GitHub license](https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge)](LICENSE)
[![scraper](https://img.shields.io/github/actions/workflow/status/elliotwutingfeng/ipsniper-info-malicious/scraper.yml?branch=main&label=SCRAPER&style=for-the-badge)](https://github.com/elliotwutingfeng/ipsniper-info-malicious/actions/workflows/scraper.yml)
<img src="https://tokei-rs.onrender.com/b1/github/elliotwutingfeng/ipsniper-info-malicious?label=Total%20Blocklist%20URLS&style=for-the-badge" alt="Total Blocklist URLs"/>

Machine-readable `.txt` blocklist of malicious URLs from ipsniper.info, updated once a day.

The URLs in this blocklist are compiled by **ipsniper.info**

**Disclaimer:** _This project is not sponsored, endorsed, or otherwise affiliated with ipsniper.info_

## Blocklist download

| File | Download |
|:-:|:-:|
| ipsniper-info-malicious-urls.txt | [:floppy_disk:](ipsniper-info-malicious-urls.txt?raw=true) |
| ipsniper-info-malicious-urls-ABP.txt | [:floppy_disk:](ipsniper-info-malicious-urls-ABP.txt?raw=true) |
| ipsniper-info-malicious-urls-UBO.txt | [:floppy_disk:](ipsniper-info-malicious-urls-UBO.txt?raw=true) |

## Requirements

-   Python >= 3.11

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
python3 scraper.py
```

## Libraries/Frameworks used

-   [BeautifulSoup4](https://beautiful-soup-4.readthedocs.io)
-   [AIOHTTP](https://docs.aiohttp.org/en/stable)

&nbsp;

<sup>These files are provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, arising from, out of or in connection with the files or the use of the files.</sup>

<sub>Any and all trademarks are the property of their respective owners.</sub>
