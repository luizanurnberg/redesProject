# Gerenciador de Senhas
## Introdução
Este projeto implementa um gerenciador de senhas que permite aos usuários armazenar e gerenciar suas senhas de forma segura. Ele utiliza técnicas de criptografia robustas para proteger os dados do usuário. Os usuários podem criar uma conta, fazer login e armazenar suas senhas com segurança.

## Funcionalidades
* Cadastro e login de usuário.
* Armazenamento seguro das senhas dos usuários usando criptografia.
* Derivação de senhas usando PBKDF2.
* Usuário e senha armazenados em um arquivo (usuário criptografado com hash SHA-256 e senhas criptografadas com AES-CBC)
* IV (Vetor de Inicialização) e chaves de criptografia armazenados em um arquivo separado criptografado com AES-EBC

## Instalação

Clone o repositório:
* git clone https://github.com/luizanurnberg/redesProject.git

