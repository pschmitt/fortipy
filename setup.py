from distutils.core import setup

setup(
    name='fortipy',
    version='0.2',
    description='FortiManger API bindings for Python',
    author='Philipp Schmitt',
    author_email='philipp.schmitt@post.lu',
    url='https://github.com/pschmitt/fortipy',
    packages=['fortipy'],
    install_requires=['requests']
)
