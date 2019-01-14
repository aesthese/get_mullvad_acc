from PIL import Image
from resizeimage import resizeimage
import requests
from time import sleep
from bs4 import BeautifulSoup
import os
import sympy
from sys import argv

# Define 2captcha.com API key in solve_captcha()
# Use -v for verbose output

def printer(message):
    if len(argv) > 1:
        if argv[1] == "-v":
            print message

def solve_captcha(imgpath):
    API_KEY = ''
    printer("[+] Uploading CAPTCHA for solving...")
    url = 'http://2captcha.com/in.php'
    data = {'key': API_KEY, 'calc': 1, 'textinstructions': 'Only return the sum of the calculation please'}
    files = {'file': open('captcha_temp_0.png', 'rb')}


    r = requests.post(url, data=data, files=files)
    id = r.text.split('|')[-1:][0]
    printer("[+] CAPTCHA ID: %s" % id)

    while True:
        req = requests.get('http://2captcha.com/res.php?key=%s&action=get&id=%s' % (API_KEY, id))
        printer("[+] Checking if solved. Response: \"%s\"" % req.text)
        if req.text == "ERROR_CAPTCHA_UNSOLVABLE":
            printer("[!] CAPTCHA ERROR. Exiting.")
            quit()
        if "OK" in req.text:
            solution = str(req.text.split('|')[-1:][0])
            if "=" in solution:
                printer("[+] Calculation returned instead of sum: %s" % solution)
                calculation = str(sympy.sympify(solution.replace('=', '')))
            printer("[+] Solution = %s" % solution)
            return solution
        sleep(5)


s = requests.session()

printer("[+] Getting Mullvad tokens and CAPTCHA image...")
req = s.get('https://mullvad.net/en/account/create/')
printer("[+] Session cookies: %s" % s.cookies.get_dict())
soup = BeautifulSoup(req.text, "html5lib")
image_tag = soup.find("img", attrs={'class': 'captcha'})

captcha_url = 'https://mullvad.net' + image_tag['src']
captcha_token = captcha_url.split('/')[-2:-1][0]
csrf_token = soup.find('input', attrs={'name': 'csrfmiddlewaretoken'})['value']

printer("[+] CSRF token: %s" % csrf_token)
printer("[+] CAPTCHA URL: %s" % captcha_url)
printer("[+] CAPTCHA token: %s" % captcha_token)


printer("[+] Saving CAPTCHA image...")
r = s.get(captcha_url, allow_redirects=True)
open('captcha_temp_0.png', 'wb').write(r.content)


data = {'csrfmiddlewaretoken': csrf_token,
        'captcha_0': captcha_token,
        'captcha_1': solve_captcha('captcha_temp_0.png')}
headers = {'user-agent': 'Mozilla Firefox Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0.',
           'content-type': 'application/x-www-form-urlencoded'}
create_req = s.post('https://mullvad.net/en/account/create/', data=data, allow_redirects=True, headers=headers)
soup = BeautifulSoup(create_req.text, "html5lib")

account_number = soup.find('input', attrs={'class': 'generated-account-number'})['value']
printer("")
printer("[+] MULLVAD ACCOUNT NUMBER: %s" % account_number)

if len(argv) > 0:
    print account_number

printer("[+] Cleaning up...")

if os.path.exists("captcha_temp_0.png"):
  os.remove("captcha_temp_0.png")
else:
  printer("[+] The file does not exist")

printer("[+] Exiting.")
