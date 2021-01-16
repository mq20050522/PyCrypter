import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog as fd
from tkinter import messagebox as msg
import json

with open('data/configuration.json','r+') as f: pass

# variables
# configuration
try:
    configure = None
    with open('data/configuration.json',encoding='utf-8') as json_file:
        configuration = json.load(json_file)
except Exception as e:
    print(e)
    configuration = {
        "password" : "password",
        "d1" : "",
        "d2" : "",
        "d3" : "",
        "d4" : "",
        "d5" : "",
        "d6" : "",
        "d7" : "",
        "d8" : "",
        "d9" : "",
        "d10" : "",
        "d11" : "",
        "d12" : "",
        "d5" : "",
        "f1" : "",
        "f2" : "",
        "f3" : "",
        "f4" : "",
        "f5" : "",
        "f6" : "",
        "f7" : "",
        "f8" : "",
        "f9" : "",
        "f10" : "",
        "f11" : "",
        "f12" : "",
    }

def feature_not_available_window():
    def exitWin():
        root.destroy()
    root = tk.Tk()
    tk.Label(root, text='Feature Currently Not Available').pack()
    tk.Button(root, text='Ok',command=exitWin).pack()


def file_in_list(file,type):
    for i in range(1,13):
        if configuration[type+str(i)] == file:
            return True
    return False

def file_at_list(file,type):    # return something like d3 or d9
    for i in range(1,13):
        if configuration[type+str(i)] == file:
            return type+str(i)

def fill_up_next_config(data, type):  # type should be string of either "d" or "f"; data is the path of file/dir
    for i in range(1,13):
        if configuration[type+str(i)] == "":
            configuration[type+str(i)] = data
            return
    for i in range(1,12):
        configuration[type+str(i)] = configuration[type+str(i+1)]
        configuration[type+"12"] = data


def saveConfiguration():
    with open('data/configuration.json','w+',encoding='utf-8') as f:
            print(configuration)
            json.dump(configuration,f)

def generateKey(password_str):
    password = password_str.encode()

    salt = b'\xc5\xeb\x92Vz/E]i\x8c\xa3\x7f\xd7u\x98K'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    print(key)
    return key

def encryptFile(file):
    if ".encrypted" in file:
        msg.showwarning(title="Warning",message="File already encrypted. "+file)
    else:
        # read data
        with open(file, 'rb') as f:
            data = f.read()
        # encrypt data
        fernet = Fernet(generateKey(configuration["password"]))
        encrypted = fernet.encrypt(data)
        # write data
        newName = file + ".encrypted"
        os.rename(file, newName)
        with open(newName, 'wb') as f:
            f.write(encrypted)

def decryptFile(file):
    if ".encrypted" not in file:
        msg.showwarning(title="Warning",message="Cannot decrypt file; encrypt the file before decrypting it. "+file)
    else:
        # open encrypted file
        with open(file, 'rb') as f:
            data = f.read()
        # decrypt data
        fernet = Fernet(generateKey(configuration["password"]))
        decrypted = fernet.decrypt(data)
        #write data
        newName = file.replace('.encrypted','')
        os.rename(file, newName)
        with open(newName, 'wb') as f:
            f.write(decrypted)

def decrypt_using_prev_name(file):
    currentName = file+".encrypted"
    # open encrypted file
    with open(currentName, 'rb') as f:
        data = f.read()
    # decrypt data
    fernet = Fernet(generateKey(configuration["password"]))
    decrypted = fernet.decrypt(data)
    #write data
    os.rename(currentName, file)
    with open(file, 'wb') as f:
        f.write(decrypted)

def mainWindow():
    root = tk.Tk()
    # main window
    # screenWid = str(int(root.winfo_screenwidth()/2))
    # screenHei = str(int(root.winfo_screenheight()/2))
    # root.geometry(screenWid+"x"+screenHei)
    root.geometry('700x350')
    root.title("PyCrypter" + "-version-alpha-v0.0.1")
    root.resizable(False,False)
    photo = tk.PhotoImage(file='data/assets/lock.png')
    root.iconphoto(True, photo)
    # root.grid_columnconfigure((0,1,2), weight=1)
    # root.configure(background='white')

    # top menu
    mainMenu = tk.Menu(root)
    fileMenu = tk.Menu(mainMenu, tearoff=False)
    toolsMenu = tk.Menu(mainMenu, tearoff=False)
    helpMenu = tk.Menu(mainMenu, tearoff=False)
    mainMenu.add_cascade(label="File", menu=fileMenu)
    mainMenu.add_cascade(label="Tools", menu=toolsMenu)
    mainMenu.add_cascade(label="Help", menu=helpMenu)
    root.config(menu=mainMenu)

    # functions 
    def encrypt_file_command():
        fileName = fd.askopenfilename()
        encryptFile(fileName)
        msg.showinfo(title="File Encrypted",message="Encryption Successful: "+fileName)
        fill_up_next_config(fileName,'f')
        root.destroy()
        mainWindow()
    def decrypt_file_command():
        fileName = fd.askopenfilename()
        decryptFile(fileName)
        msg.showinfo(title="File Encrypted",message="Decryption Successful: "+fileName)
        if file_in_list(fileName,'f'):
            configuration[file_at_list()] = ""
        root.destroy()
        mainWindow()

    # file menu
    fileMenu.add_command(label="Encrypt File",command=encrypt_file_command)
    fileMenu.add_command(label="Decrypt File",command=decrypt_file_command)
    toolsMenu.add_command(label="Preferences",command=feature_not_available_window)
    helpMenu.add_command(label="About",command=feature_not_available_window)


    # top part variables
    currentPassword = configuration['password']
    locked = tk.BooleanVar(root)
    entryState = "normal"
    
    # top part functions
    def setCanEditEntry():
        if locked.get():
            passwordEntry.config(state='readonly')
        else:
            passwordEntry.config(state='normal')
    def set_password_to_default():
        passwordEntry.delete(0,'end')
        passwordEntry.insert(0,configuration["password"])
    def save_current_password():
        configuration["password"] = passwordEntry.get()
        saveConfiguration()

    # top part
    passwordLabel = tk.Label(root, text='Current Encryption Password')
    passwordEntry = tk.Entry(root,textvariable=configuration["password"],state=entryState)
    passwordEntry.insert(0,configuration["password"])
    lockCheck = tk.Checkbutton(root,text='Lock',variable=locked,command=setCanEditEntry)
    backButton = tk.Button(root,text="Back",command=set_password_to_default)
    saveButton = tk.Button(root,text="Save",command=save_current_password)

    #set location
    passwordLabel.grid(row=0,column=1)
    passwordEntry.grid(row=0,column=2)
    lockCheck.grid(row=0,column=3)
    backButton.grid(row=1,column=1)
    saveButton.grid(row=1,column=2)
    
    # lower part left directories
    directoryTree = ttk.Treeview(root,height=12,columns=('col1'),show='headings')
    fileTree = ttk.Treeview(root,height=12,columns=('col1'),show='headings')

    # set name
    directoryTree.column("col1",width=150,anchor='center')
    directoryTree.heading('col1',text='Directories')
    fileTree.column("col1",width=500,anchor='center')
    fileTree.heading('col1',text='Files')

    # set location
    directoryTree.grid(row=5,column=1)
    fileTree.grid(row=5,column=2,columnspan=7)

    # add directories
    d1 = directoryTree.insert("",0,"d1",text=configuration['d1'],values=(configuration['d1']),open=True)
    d2 = directoryTree.insert("",0,"d2",text=configuration['d2'],values=(configuration['d2']),open=True)
    d3 = directoryTree.insert("",0,"d3",text=configuration['d3'],values=(configuration['d3']),open=True)
    d4 = directoryTree.insert("",0,"d4",text=configuration['d4'],values=(configuration['d4']),open=True)
    d5 = directoryTree.insert("",0,"d5",text=configuration['d5'],values=(configuration['d5']),open=True)
    d6 = directoryTree.insert("",0,"d6",text=configuration['d6'],values=(configuration['d6']),open=True)
    d7 = directoryTree.insert("",0,"d7",text=configuration['d7'],values=(configuration['d7']),open=True)
    d8 = directoryTree.insert("",0,"d8",text=configuration['d8'],values=(configuration['d8']),open=True)
    d9 = directoryTree.insert("",0,"d9",text=configuration['d9'],values=(configuration['d9']),open=True)
    d10 = directoryTree.insert("",0,"d10",text=configuration['d10'],values=(configuration['d10']),open=True)
    d11 = directoryTree.insert("",0,"d11",text=configuration['d11'],values=(configuration['d11']),open=True)
    d12 = directoryTree.insert("",0,"d12",text=configuration['d12'],values=(configuration['d12']),open=True)

    # add files
    f1 = fileTree.insert("",0,"f1",text=configuration['f1'],values=(configuration['f1']),open=True)
    f2 = fileTree.insert("",0,"f2",text=configuration['f2'],values=(configuration['f2']),open=True)
    f3 = fileTree.insert("",0,"f3",text=configuration['f3'],values=(configuration['f3']),open=True)
    f4 = fileTree.insert("",0,"f4",text=configuration['f4'],values=(configuration['f4']),open=True)
    f5 = fileTree.insert("",0,"f5",text=configuration['f5'],values=(configuration['f5']),open=True)
    f6 = fileTree.insert("",0,"f6",text=configuration['f6'],values=(configuration['f6']),open=True)
    f7 = fileTree.insert("",0,"f7",text=configuration['f7'],values=(configuration['f7']),open=True)
    f8 = fileTree.insert("",0,"f8",text=configuration['f8'],values=(configuration['f8']),open=True)
    f9 = fileTree.insert("",0,"f9",text=configuration['f9'],values=(configuration['f9']),open=True)
    f10 = fileTree.insert("",0,"f10",text=configuration['f10'],values=(configuration['f10']),open=True)
    f11 = fileTree.insert("",0,"f11",text=configuration['f11'],values=(configuration['f11']),open=True)
    f12 = fileTree.insert("",0,"f12",text=configuration['f12'],values=(configuration['f12']),open=True)

    # clear configuration files and directories
    def clear_configuration_directories():
        for i in range(1,13):
            configuration["d"+str(i)] = ""
        saveConfiguration()
        root.destroy()
        mainWindow()
    def clear_configuration_files():
        for i in range(1,13):
            configuration['f'+str(i)] = ""
        saveConfiguration()
        root.destroy()
        mainWindow()
    

    # tree double click reaction
    def directoryWindow(event):
        top = tk.Toplevel(root)
        top.geometry("350x300")
        top.title("Select directories to encrypt")
        top.grab_set()
        top.grid_columnconfigure(0,weight=0)
        top.focus()
        top.resizable(False,False)
        # functions
        def cancelPressed():
            top.destroy()
        # update configuration files and directories
        def update_configuration_directories():
            configuration['d1'] = d1e.get()
            configuration['d2'] = d2e.get()
            configuration['d3'] = d3e.get()
            configuration['d4'] = d4e.get()
            configuration['d5'] = d5e.get()
            configuration['d6'] = d6e.get()
            configuration['d7'] = d7e.get()
            configuration['d8'] = d8e.get()
            configuration['d9'] = d9e.get()
            configuration['d10'] = d10e.get()
            configuration['d11'] = d11e.get()
            configuration['d12'] = d12e.get()
            saveConfiguration()
            root.destroy()
            mainWindow()

        # entries
        d1e = tk.Entry(top,textvariable=configuration["d1"],state=entryState,width=50)
        d2e = tk.Entry(top,textvariable=configuration["d2"],state=entryState,width=50)
        d3e = tk.Entry(top,textvariable=configuration["d3"],state=entryState,width=50)
        d4e = tk.Entry(top,textvariable=configuration["d4"],state=entryState,width=50)
        d5e = tk.Entry(top,textvariable=configuration["d5"],state=entryState,width=50)
        d6e = tk.Entry(top,textvariable=configuration["d6"],state=entryState,width=50)
        d7e = tk.Entry(top,textvariable=configuration["d7"],state=entryState,width=50)
        d8e = tk.Entry(top,textvariable=configuration["d8"],state=entryState,width=50)
        d9e = tk.Entry(top,textvariable=configuration["d9"],state=entryState,width=50)
        d10e = tk.Entry(top,textvariable=configuration["d10"],state=entryState,width=50)
        d11e = tk.Entry(top,textvariable=configuration["d11"],state=entryState,width=50)
        d12e = tk.Entry(top,textvariable=configuration["d12"],state=entryState,width=50)
        # inserts
        d1e.insert(0,configuration["d1"])
        d2e.insert(0,configuration["d2"])
        d3e.insert(0,configuration["d3"])
        d4e.insert(0,configuration["d4"])
        d5e.insert(0,configuration["d5"])
        d6e.insert(0,configuration["d6"])
        d7e.insert(0,configuration["d7"])
        d8e.insert(0,configuration["d8"])
        d9e.insert(0,configuration["d9"])
        d10e.insert(0,configuration["d10"])
        d11e.insert(0,configuration["d11"])
        d12e.insert(0,configuration["d12"])
        cancelButton = tk.Button(top,text="Cancel",command=cancelPressed)
        decryptButton = tk.Button(top,text="Decrypt",command=clear_configuration_directories)
        encryptButton = tk.Button(top,text="Encrypt",command=update_configuration_directories)
        # grid
        d1e.grid(row=0,column=0,columnspan=3)
        d2e.grid(row=1,column=0,columnspan=3)
        d3e.grid(row=2,column=0,columnspan=3)
        d4e.grid(row=3,column=0,columnspan=3)
        d5e.grid(row=4,column=0,columnspan=3)
        d6e.grid(row=5,column=0,columnspan=3)
        d7e.grid(row=6,column=0,columnspan=3)
        d8e.grid(row=7,column=0,columnspan=3)
        d9e.grid(row=8,column=0,columnspan=3)
        d10e.grid(row=9,column=0,columnspan=3)
        d11e.grid(row=10,column=0,columnspan=3)
        d12e.grid(row=11,column=0,columnspan=3)
        cancelButton.grid(row=12,column=0)
        decryptButton.grid(row=12,column=1)
        encryptButton.grid(row=12,column=2)

    def fileWindow(event):
        top = tk.Toplevel(root)
        top.geometry("350x300")
        top.title("Select files to encrypt")
        top.grab_set()
        top.grid_columnconfigure(0,weight=0)
        top.focus()
        top.resizable(False,False)
        # functions
        def cancelPressed():
            top.destroy()
        # update configuration files and directories
        def update_configuration_files():
            configuration['f1'] = f1e.get()
            configuration['f2'] = f2e.get()
            configuration['f3'] = f3e.get()
            configuration['f4'] = f4e.get()
            configuration['f5'] = f5e.get()
            configuration['f6'] = f6e.get()
            configuration['f7'] = f7e.get()
            configuration['f8'] = f8e.get()
            configuration['f9'] = f9e.get()
            configuration['f10'] = f10e.get()
            configuration['f11'] = f11e.get()
            configuration['f12'] = f12e.get()
            saveConfiguration()
            root.destroy()
            mainWindow()
        # entries
        f1e = tk.Entry(top,textvariable=configuration["f1"],state=entryState,width=50)
        f2e = tk.Entry(top,textvariable=configuration["f2"],state=entryState,width=50)
        f3e = tk.Entry(top,textvariable=configuration["f3"],state=entryState,width=50)
        f4e = tk.Entry(top,textvariable=configuration["f4"],state=entryState,width=50)
        f5e = tk.Entry(top,textvariable=configuration["f5"],state=entryState,width=50)
        f6e = tk.Entry(top,textvariable=configuration["f6"],state=entryState,width=50)
        f7e = tk.Entry(top,textvariable=configuration["f7"],state=entryState,width=50)
        f8e = tk.Entry(top,textvariable=configuration["f8"],state=entryState,width=50)
        f9e = tk.Entry(top,textvariable=configuration["f9"],state=entryState,width=50)
        f10e = tk.Entry(top,textvariable=configuration["f10"],state=entryState,width=50)
        f11e = tk.Entry(top,textvariable=configuration["f11"],state=entryState,width=50)
        f12e = tk.Entry(top,textvariable=configuration["f12"],state=entryState,width=50)
        # inserts
        f1e.insert(0,configuration["f1"])
        f2e.insert(0,configuration["f2"])
        f3e.insert(0,configuration["f3"])
        f4e.insert(0,configuration["f4"])
        f5e.insert(0,configuration["f5"])
        f6e.insert(0,configuration["f6"])
        f7e.insert(0,configuration["f7"])
        f8e.insert(0,configuration["f8"])
        f9e.insert(0,configuration["f9"])
        f10e.insert(0,configuration["f10"])
        f11e.insert(0,configuration["f11"])
        f12e.insert(0,configuration["f12"])

        cancelButton = tk.Button(top,text="Cancel",command=cancelPressed)
        decryptButton = tk.Button(top,text="Decrypt",command=clear_configuration_files)
        encryptButton = tk.Button(top,text="Encrypt",command=update_configuration_files)
        # grid
        f1e.grid(row=0,column=0,columnspan=3)
        f2e.grid(row=1,column=0,columnspan=3)
        f3e.grid(row=2,column=0,columnspan=3)
        f4e.grid(row=3,column=0,columnspan=3)
        f5e.grid(row=4,column=0,columnspan=3)
        f6e.grid(row=5,column=0,columnspan=3)
        f7e.grid(row=6,column=0,columnspan=3)
        f8e.grid(row=7,column=0,columnspan=3)
        f9e.grid(row=8,column=0,columnspan=3)
        f10e.grid(row=9,column=0,columnspan=3)
        f11e.grid(row=10,column=0,columnspan=3)
        f12e.grid(row=11,column=0,columnspan=3)
        cancelButton.grid(row=12,column=0)
        decryptButton.grid(row=12,column=1)
        encryptButton.grid(row=12,column=2)

    directoryTree.bind("<Double-1>", directoryWindow)
    fileTree.bind("<Double-1>", fileWindow)

    root.mainloop()

if __name__ == '__main__':
    # decrypt_using_prev_name('C:/Users/mingqianli/OneDrive/Desktop/test.txt')
    mainWindow()
    print('done')