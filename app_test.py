import time

import pytest
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

app_url = 'https://pw-dev.djones.co/'

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
    driver.get(app_url)
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
    driver.get(app_url)
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

def test_create_record(driver):
    title = 'test'
    url = 'http://example.com/'
    username = 'test'
    other = 'This is a test.'
    driver.get(app_url)
    driver.find_element_by_name('title').send_keys(title)
    driver.find_element_by_name('url').send_keys(url)
    driver.find_element_by_name('username').send_keys(username)
    el = driver.find_element_by_name('other')
    el.send_keys(other)
    el.submit()
    wait_for_stale(driver, el)
    el = driver.find_elements_by_css_selector('.panel-body .row .col-sm-9')
    assert el[0].text == title
    assert el[1].text == url
    assert el[2].text == username
    assert el[3].text == '••••••••'
    assert len(
        el[3].find_element_by_css_selector('button.cb-copy')
        .get_attribute('data-clipboard-text')
    ) == 16
    assert el[4].text == other


def test_edit_record(driver):
    title = 'test'
    url = 'http://example.com/'
    username = 'test'
    other = 'This is a test.'
    edited = ' edited'
    driver.get(app_url)
    driver.find_element_by_link_text('All Records').click()
    driver.execute_script(
        'return document.querySelector(\'[href^="/edit/"]\')'
    ).click()
    driver.find_element_by_name('title').send_keys(edited)
    driver.find_element_by_name('url').send_keys(edited)
    driver.find_element_by_name('username').send_keys(edited)
    driver.find_element_by_name('password').send_keys(edited)
    el = driver.find_element_by_name('other')
    el.send_keys(edited)
    el.submit()
    wait_for_stale(driver, el)
    el = driver.find_elements_by_css_selector('.panel-body .row .col-sm-9')
    assert el[0].text == title + edited
    assert el[1].text == url + edited
    assert el[2].text == username + edited
    assert el[3].text == '••••••••'
    assert (
        el[3].find_element_by_css_selector('button.cb-copy')
        .get_attribute('data-clipboard-text')
    )[16:] == edited
    assert el[4].text == other + edited

def test_search(driver):
    driver.get(app_url)
    el = driver.find_element_by_name('q')
    el.send_keys('edited')
    el.submit()
    wait_for_stale(driver, el)
    el = driver.find_element_by_css_selector('.container .alert')
    assert '1' in el.text

def test_save_search(driver):
    driver.get(app_url)
    el = driver.find_element_by_name('q')
    el.send_keys('test')
    el.submit()
    wait_for_stale(driver, el)
    driver.find_element_by_link_text('Saved Searches').click()
    driver.find_element_by_link_text('Save This Search').click()
    el = driver.find_element_by_css_selector('.container .alert')
    assert 'Search term saved.' in el.text
    driver.find_element_by_link_text('Saved Searches').click()
    driver.find_element_by_link_text('test').click()
    el = driver.find_element_by_css_selector('.container .alert')
    assert '1' in el.text


def test_change_password():
    pass
