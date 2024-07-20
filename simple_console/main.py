import string
import secrets

def contains_upper(password: str) -> bool:
    """Checks whether a password contains uppercase characters"""
    # checks each symbol
    for char in password:
        if char.isupper():
            return True
        
    return False

def contains_symbols(password: str) -> bool:
    """Checks whether a password contains symbols"""
    # checks if there is a character from punctuation(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~) 
    for char in password:
        if char in string.punctuation:
            return True
        
    return False

def generate_password(length: int = 10, symbols: bool = True, uppercase: bool = True):
    """
    Generates a password based on the users specifications

    :param length: The length of the password
    :param symbols: Password should include symbols
    :param uppercase: Password should include uppercase letters
    :return: str
    """

    # Create a combination of characters to choose from
    combination: str = string.ascii_lowercase + string.digits
    
    # If the user wants symbols, add punctuation to the combination
    if symbols:
        combination += string.punctuation

    # If the user wants uppercase, add uppercase to the combination
    if uppercase:
        combination += string.ascii_uppercase
    
    # Get the length of the combination characters
    combination_length = len(combination)

    # Create a new password variable
    new_password: str = ""

    # Append to the new_password a new random character for each iteration
    for _ in range(length):
        new_password += combination[secrets.randbelow(combination_length)]

    return new_password

if __name__ == "__main__":
    specify_options = str(input("Specify password options? (y / n) "))

    if specify_options == "y":
        pass_length = int(input("Length of password: "))
        pass_symbols = True if input("Include symbols? (y / n) ") == "y" else False
        pass_uppercase = True if input("Include uppercase letters? (y / n) ") == "y" else False
        new_pass: str = generate_password(pass_length, pass_symbols, pass_uppercase)
    else:
        new_pass: str = generate_password()

    specs: str = f"Uppercase: {contains_upper(new_pass)}, Symbols: {contains_symbols(new_pass)}"
    print(f"{new_pass} ({specs})")