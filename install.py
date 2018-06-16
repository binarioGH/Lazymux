from os import system
print("Installing lazymux...")
system("mv lazymux.py /bin/")
system("mv core /bin/")
system("mv /bin/lazymux.py /bin/lazymux")
system("chmod +x /bin/lazymux")
print("Please type 'lazymux' in the console.")