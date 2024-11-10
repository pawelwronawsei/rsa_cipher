import tkinter as tk
import sympy as sp

valid_alphabet = ['a', 'ą', 'b', 'c', 'ć', 'd', 'e', 'ę', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'ł',
                  'm', 'n', 'ń', 'o', 'ó', 'p', 'q', 'r', 's', 'ś', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ź', 'ż']


def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()

def choose_e(phi):
    e = sp.randprime(2, phi)
    while sp.gcd(e, phi) != 1:
        e = sp.randprime(2, phi)
    return e


def encrypt():
    text_to_encrypt = encrypt_entry1.get().lower()
    p_input = encrypt_entry2.get()
    q_input = encrypt_entry3.get()

    # Check for valid integer inputs and that p and q are prime
    if not p_input.isdigit() or not q_input.isdigit():
        encrypt_response.config(text="Błąd: Wprowadź poprawne liczby całkowite dla p i q.")
        return

    p, q = int(p_input), int(q_input)

    if not (sp.isprime(p) and sp.isprime(q)):
        encrypt_response.config(text="Błąd: p i q muszą być liczbami pierwszymi.")
        return

    # Filter out invalid characters
    text_to_encrypt = [char for char in text_to_encrypt if char in valid_alphabet]
    if len(text_to_encrypt) == 0:
        encrypt_response.config(text="Wprowadzony tekst jest niepoprawny!")
        return

    # Calculate n, phi, and keys
    n = p * q
    phi = (p - 1) * (q - 1)
    e = choose_e(phi)
    d = sp.mod_inverse(e, phi)

    encrypted_message = [str(pow(ord(char), e, n)) for char in text_to_encrypt]
    encrypt_response.config(text=' '.join(encrypted_message))

    # Display encryption key info for user reference
    encrypt_key_info.config(text=f"Klucz publiczny (n, e): ({n}, {e}), Klucz prywatny (d): {d}")


def decrypt():
    encrypted_message = decrypt_entry1.get().split(' ')
    p_input = decrypt_entry2.get()
    q_input = decrypt_entry3.get()
    d_input = decrypt_entry4.get()

    # Validate integer inputs for p, q, and d
    if not p_input.isdigit() or not q_input.isdigit() or not d_input.isdigit():
        decrypt_response.config(text="Błąd: Wprowadź poprawne liczby całkowite dla p, q oraz d.")
        return

    p, q, d = int(p_input), int(q_input), int(d_input)

    if not (sp.isprime(p) and sp.isprime(q)):
        decrypt_response.config(text="Błąd: p i q muszą być liczbami pierwszymi.")
        return

    # Calculate n for decryption
    n = p * q
    decrypted_message = []

    for char in encrypted_message:
        try:
            decrypted_int = pow(int(char), d, n)
            if decrypted_int < 256:
                decrypted_message.append(chr(decrypted_int))
            else:
                decrypted_message.append(valid_alphabet[decrypted_int % len(valid_alphabet)])
        except ValueError:
            decrypt_response.config(text="Błąd: Wprowadzona wiadomość jest niepoprawna.")
            return

    decrypt_response.config(text=''.join(decrypted_message))


#GŁÓWNE OKNO
root = tk.Tk()
root.title("RSA Szyfrowanie/Deszyfrowanie")
root.geometry("1000x900")
root.configure(bg="#1A1A1A")

#BOX DO SZYFROWANIA
encrypt_box = tk.Frame(root, padx=15, pady=15, bg="#000000", relief="ridge", bd=2)
encrypt_box.pack(pady=20)

encrypt_label0 = tk.Label(encrypt_box, text="SZYFROWANIE", bg="#000000", fg="#FFFFFF", font=("Arial", 18, "bold"))
encrypt_label0.grid(row=0, column=0, columnspan=2, pady=10)

encrypt_label1 = tk.Label(encrypt_box, text="Tekst do zaszyfrowania:", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
encrypt_label1.grid(row=1, column=0, pady=10, sticky="w")

encrypt_entry1 = tk.Entry(encrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
encrypt_entry1.grid(row=1, column=1, pady=10)

encrypt_label2 = tk.Label(encrypt_box, text="p (liczba pierwsza):", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
encrypt_label2.grid(row=2, column=0, pady=10, sticky="w")

encrypt_entry2 = tk.Entry(encrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
encrypt_entry2.grid(row=2, column=1, pady=10)

encrypt_label3 = tk.Label(encrypt_box, text="q (liczba pierwsza):", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
encrypt_label3.grid(row=3, column=0, pady=10, sticky="w")

encrypt_entry3 = tk.Entry(encrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
encrypt_entry3.grid(row=3, column=1, pady=10)

encrypt_btn = tk.Button(encrypt_box, text="Szyfruj", command=encrypt, bg="#FFFFFF", fg="#000000", font=("Arial", 12, "bold"), relief="flat", padx=10)
encrypt_btn.grid(row=4, column=0, columnspan=2, pady=10)

encrypt_response = tk.Label(encrypt_box, text="", bg="#000000", fg="#B0E57C", font=("Arial", 12))
encrypt_response.grid(row=5, column=0, columnspan=2)

encrypt_copy_btn = tk.Button(encrypt_box, text="Kopiuj", command=lambda: copy_to_clipboard(encrypt_response.cget("text")), bg="#FFFFFF", fg="#000000", font=("Arial", 10), relief="flat")
encrypt_copy_btn.grid(row=6, column=1, sticky="e")

encrypt_key_info = tk.Label(encrypt_box, text="", bg="#000000", fg="#FFFFFF", font=("Arial", 10))
encrypt_key_info.grid(row=7, column=0, columnspan=2)

# Frame for decryption
decrypt_box = tk.Frame(root, padx=15, pady=15, bg="#000000", relief="ridge", bd=2)
decrypt_box.pack(pady=20)

decrypt_label0 = tk.Label(decrypt_box, text="ODSZYFROWANIE", bg="#000000", fg="#FFFFFF", font=("Arial", 18, "bold"))
decrypt_label0.grid(row=0, column=0, columnspan=2, pady=10)

decrypt_label1 = tk.Label(decrypt_box, text="Zaszyfrowana wiadomość (oddzielona spacjami)", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
decrypt_label1.grid(row=1, column=0, pady=10, sticky="w")

decrypt_entry1 = tk.Entry(decrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
decrypt_entry1.grid(row=1, column=1, pady=10)

decrypt_label2 = tk.Label(decrypt_box, text="p (liczba pierwsza):", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
decrypt_label2.grid(row=2, column=0, pady=10, sticky="w")

decrypt_entry2 = tk.Entry(decrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
decrypt_entry2.grid(row=2, column=1, pady=10)

decrypt_label3 = tk.Label(decrypt_box, text="q (liczba pierwsza):", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
decrypt_label3.grid(row=3, column=0, pady=10, sticky="w")

decrypt_entry3 = tk.Entry(decrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
decrypt_entry3.grid(row=3, column=1, pady=10)

decrypt_label4 = tk.Label(decrypt_box, text="d:", bg="#000000", fg="#FFFFFF", font=("Arial", 12))
decrypt_label4.grid(row=4, column=0, pady=10, sticky="w")

decrypt_entry4 = tk.Entry(decrypt_box, width=30, bg="#1A1A1A", fg="#FFFFFF", insertbackground="#FFFFFF", font=("Arial", 12))
decrypt_entry4.grid(row=4, column=1, pady=10)

decrypt_btn = tk.Button(decrypt_box, text="Odszyfruj", command=decrypt, bg="#FFFFFF", fg="#000000", font=("Arial", 12, "bold"), relief="flat", padx=10)
decrypt_btn.grid(row=5, column=0, columnspan=2, pady=10)

decrypt_response = tk.Label(decrypt_box, text="", bg="#000000", fg="#B0E57C", font=("Arial", 12))
decrypt_response.grid(row=6, column=0, columnspan=2)

decrypt_copy_btn = tk.Button(decrypt_box, text="Kopiuj", command=lambda: copy_to_clipboard(decrypt_response.cget("text")), bg="#FFFFFF", fg="#000000", font=("Arial", 10), relief="flat")
decrypt_copy_btn.grid(row=6, column=1, sticky="e")

#ODPALA APLIKACJE
root.mainloop()
