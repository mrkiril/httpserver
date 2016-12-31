from setuptools import setup, find_packages
from os.path import join, dirname
setup(
    name = "httpserver",
    version = "0.1",
    packages = find_packages()+["pages",""],  # include all packages under src    
    include_package_data = True,    # include everything in source control  
    
    #package_dir={'':'pages'},
    package_data={'pages': ['*.html']},
    #data_files=[('', ['requirements.txt'])],
   

    #install_requires=['sys', 'math', 'os', "logging", "multiprocessing", "email.utils"],
    # metadata for upload to PyPI
    author = "Kyrylo Kukhelnyi",
    author_email = "mrkiril@ukr.net",    
    keywords = "python server",
    test_suite='tests.test_serv',
    description="Simple python http server serv serv serv",
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    license = "BSD",
)