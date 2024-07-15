import re
import random
import string
import base64
import getpass

def password_strength_checker(password):
    if len(password) < 8:
        return "Too short"
    elif re.search("[a-z]", password) is None:
        return "Missing lowercase characters"
    elif re.search("[A-Z]", password) is None:
        return "Missing uppercase characters"
    elif re.search("[0-9]", password) is None:
        return "Missing numbers"
    elif re.search("[!@#\$%\^&\*]", password) is None:
        return "Missing special characters"
    else:
        return "Strong password"

def get_strong_password(masked=False):
    while True:
        if masked:
            password = getpass.getpass("Enter your password (will be masked): ")
        else:
            password = input("Enter your password: ")
        password_strength = password_strength_checker(password)
        if password_strength == "Strong password":
            return password
        elif password_strength == "Too short":
            choice = input("Password is too short. Do you want to retype the password or generator a new password? (Retype/Generate):")
            if choice.lower() == "retype":
                continue
            elif choice.lower() == "generate":
                password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*()", k=8))
                print("Generated password:", password)
                return password
            else:
                print("Invalid choice.")
                continue
        else:
            print("Password strength:", password_strength)
            print("Please add the missing elements to make it a stronger password")
            continue

print("Welcome to the Password Strength Checker and Encryptor!")

masking_choice = input("Do you want to type the password by masking it? (Yes/No): ")
if masking_choice.lower() == "yes":
    password = get_strong_password(masked=True)
else:
    password = get_strong_password()

print("Password accepted.")

encryption_choice = input("Do you want to secure the password by encrypting it? (Yes/No): ")
if encryption_choice.lower() == "yes":
    password_bytes = password.encode('utf-8')
    encoded_password = base64.b64encode(password_bytes)
    print("Encrypted password:", encoded_password)
    decryption_choice = input("Do you want to decrypt the password? (Yes/No): ")
    if decryption_choice.lower() == "yes":
       decoded_password_bytes = base64.b64decode(encoded_password)
       decoded_password = decoded_password_bytes.decode('utf-8') 
       print("Decrypted password:", decoded_password)
    else:
       print("password nit decrypted.")
else:
   print("password not encrypted.")

print("Thank you for using the Password Strength Checker and Encryptor.")

