import os, threefish, cramer, custom_md5
from base64 import b64encode, b64decode

def main_menu():
	print("Séléctionner votre fonction de chiffrement")
	print("->1<- Chiffrement symétrique ThreeFish")
	print("->2<- Chiffrement de Cramer-Shoup")
	print("->3<- Hashage d’un message")
	print("->4<- Déchiffrement symétrique ThreeFish")
	print("->5<- Déchiffrement de Cramer-Shoup")
	print("->6<- Vérification d’un Hash")

	while True:
		choice = int(input())
		if choice == 1:
			threefish_results = threefish_encrypt_menu()
			if threefish_results is None:
				main_menu()
				break
			threefish.encrypt_threeFish(threefish_results.get("file_path"), threefish_results.get("output_file_path"),
										threefish_results.get("key"), threefish_results.get("block_cipher_mode"))
			print("-----------------------------------------------------------------------------------------")
			main_menu()
		elif choice == 4:
			threefish_results = threefish_decrypt_menu()
			if None in threefish_results:
				main_menu()
				break

			threefish.decrypt_threeFish(threefish_results.get("file_path"),
											threefish_results.get("output_file_path"), threefish_results.get("key"),
											threefish_results.get("block_cipher_mode"))
			print("-----------------------------------------------------------------------------------------")
			main_menu()
		elif choice == 2:
			cramer_results = cramer_encrypt_menu()
			if cramer_results is None:
				main_menu()
				break
			cramer.encrypt_file(cramer_results.get("file_path"), cramer_results.get("output_file_path"))
			print("-----------------------------------------------------------------------------------------")
			main_menu()
		elif choice == 5:
			cramer_results = cramer_decrypt_menu()
			if cramer_results is None:
				main_menu()
				break
			cramer.decrypt_file(cramer_results.get("file_path"), cramer_results.get("output_file_path"))
			print("-----------------------------------------------------------------------------------------")
			main_menu()
		elif choice == 3:
			hash_results = hash_menu()
			if hash_results is None:
				main_menu()
				break
			print('Le hash du message est : ')
			print(custom_md5.md5(hash_results.get("message")))
			print("-----------------------------------------------------------------------------------------")
			main_menu()
		elif choice == 6:
			hash_results = verif_menu()
			if hash_results is None:
				main_menu()
				break
			print('Le fichier et le hash ' + custom_md5.check(hash_results.get("file_path"),hash_results.get("hash")))
			print("-----------------------------------------------------------------------------------------")
			main_menu()
		else:
			print("Option non correct, entrer un nombre correspondant à une option du menu : ")


def threefish_encrypt_menu():
	file_path = select_file()
	output_file_path = input("\nEntrer le chemin de sortie du fichier chiffré : ")
	key = select_key()
	if key is None:
		return
	block_cipher_mode = select_block_cipher_mode()
	if block_cipher_mode is None:
		return
	return {"file_path": file_path, "output_file_path": output_file_path, "key": key, "block_cipher_mode": block_cipher_mode}


def threefish_decrypt_menu():
	file_path = select_file()
	output_file_path = input("\nEntrer le chemin de sortie du fichier déchiffré : ")
	key = b64decode(input("\nEntrer la clé de déchiffrement : "))
	block_cipher_mode = select_block_cipher_mode()
	return {"file_path":file_path, "output_file_path":output_file_path, "key":key, "block_cipher_mode":block_cipher_mode}

def cramer_encrypt_menu():
	file_path = select_file()
	output_file_path = input("\nEntrer le chemin de sortie du fichier chiffré : ")
	return {"file_path":file_path, "output_file_path":output_file_path}

def cramer_decrypt_menu():
	file_path = select_file()
	output_file_path = input("\nEntrer le chemin de sortie du fichier déchiffré : ")
	return {"file_path":file_path, "output_file_path":output_file_path}

def hash_menu():
	message = input("\nEntrer le message que vous voulez hasher : ")
	message = bytes(message, encoding="utf-8")
	return {"message":message}

def verif_menu():
	file_path = select_file()
	message = input("\nEntrer le hash que vous voulez vérifier : ")
	message = message[:32]
	return {"file_path":file_path, "hash":message}

def select_file():
	while True:
		file_path = input("\nEntrer le chemin du fichier : ")
		if os.path.isfile(file_path):
			return file_path
		else:
			print("Le fichier n'existe pas")


def select_block_cipher_mode():
	block_cipher_modes = {
		1: "ECB",
		2: "CBC"
	}

	print("\nSelectionner votre mode de chiffrement par bloc")
	print("1 - Electronic Code Book (ECB)")
	print("2 - Cipher Block Chaining (CBC)")
	print("3 - Return")
	choice = int(input())

	if choice == 3:
		return

	block_cipher_mode = block_cipher_modes.get(choice, "invalid")
	while block_cipher_mode == "invalid":
		choice = int(input("Option non correct, entrer un nombre correspondant à une option du menu : "))
		if choice == 3:
			return
		block_cipher_mode = block_cipher_modes.get(choice, "invalid")

	return block_cipher_mode


def select_key():
	print("\nChoisir une clé de chiffrement")
	print("1 - Générer aléatoirement une clé")
	print("2 - Clé personnalisée (base64)")
	print("3- Return")

	while True:
		choice = int(input())
		if choice == 1:
			while True:
				key_size = int(input("\nEntrer la taille de la clé souhaitée (256/512/1024 bits) : "))
				if key_size in threefish.VALID_BLOCK_SIZES:
					key = b64encode(os.urandom(int(key_size / 8))).decode("utf-8")
					print("\n-----------------------------------------------------------------------------------------")
					print("Clé de chiffrement (à conserver) : ", key)
					print("-----------------------------------------------------------------------------------------")
					return b64decode(key)
				else:
					print("\nTaille de clé ", key_size, " invalide")
		elif choice == 2:
			while True:
				try:
					key = b64decode(input("\nEntrer la clé de chiffrement (taille de la clé : 256/512/1024 bits) encodée en base64 : "))
					if (len(key) * 8) in threefish.VALID_BLOCK_SIZES:
						return key
					else:
						print("\nTaille de clé ", (len(key) * 8), " invalide")
				except:
					print("\nClé invalide")
		elif choice == 3:
			return
		else:
			print("Option non correct, entrer un nombre correspondant à une option du menu : ")


main_menu()
