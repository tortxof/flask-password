import time

import pytest
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def wait_for_stale(driver, el):
    WebDriverWait(driver, 10).until(EC.staleness_of(el))

@pytest.fixture(scope='module')
def credentials():
    return (f'test-{str(int(time.time()))}', '12345678')

@pytest.fixture(scope='module')
def driver():
    myDriver = webdriver.Remote(
       command_executor='http://127.0.0.1:4444',
       desired_capabilities=DesiredCapabilities.FIREFOX,
    )
    yield myDriver
    myDriver.close()

def test_create_user(driver, credentials):
    driver.get("https://pw-dev.djones.co/")
    el = driver.find_element_by_link_text("Sign Up")
    el.click()
    el = driver.find_element_by_name('username')
    el.clear()
    el.send_keys(credentials[0])
    el = driver.find_element_by_name('password')
    el.clear()
    el.send_keys(credentials[1])
    el.submit()
    wait_for_stale(driver, el)
    el = driver.find_element_by_css_selector('.container .alert')
    assert 'has been created' in el.text
    assert credentials[0] in el.text

def test_login(driver, credentials):
    driver.get("https://pw-dev.djones.co/")
    el = driver.find_element_by_link_text("Log In")
    el.click()
    el = driver.find_element_by_name('username')
    el.clear()
    el.send_keys(credentials[0])
    el = driver.find_element_by_name('password')
    el.clear()
    el.send_keys(credentials[1])
    el.submit()
    wait_for_stale(driver, el)
    el = driver.find_element_by_css_selector('.container .alert')
    assert 'You are logged in.' in el.text

# el = driver.find_element_by_name('username')
# el.clear()
# el.send_keys(username)
# el = driver.find_element_by_name('password')
# el.clear()
# el.send_keys('12345678')
# el.submit()
# wait_for_stale(driver, el)
# el = driver.find_element_by_name('title')
# el.clear()
# el.send_keys('test 1')
# el = driver.find_element_by_name('url')
# el.clear()
# el.send_keys('http://www.example.com/')
# el = driver.find_element_by_css_selector('.panel form button')
# el.click()
# wait_for_stale(driver, el)
# el = driver.find_element_by_name('q')
# el.clear()
# el.send_keys('test')
# el.submit()
# wait_for_stale(driver, el)
# time.sleep(10)
# driver.close()
