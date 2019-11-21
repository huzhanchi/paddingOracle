#!/usr/bin/ruby -w
require 'openssl'
require 'base64'
require 'socket'

def banner()
    puts ' ____________________________________________'
    puts '|                                            |'
    puts '| Welcome to our secure communication system |'
    puts '| Our system is secured by AES               |'    
    puts '| So...No key! No Message!                   |'
    puts '|____________________________________________|'
    puts ''
    puts output_secret
end

def option()
	$client.puts '1. Get the secret message.'
	$client.puts '2. Encrypt the message'
	$client.puts '3. Decrypt the message.'
	$client.puts 'Give your option:'
end

def init()
    file_key=File.new("./aeskey","r")
    $key=file_key.gets
    file_key.close()
end
def aes_encrypt(iv,data)
    cipher = OpenSSL::Cipher::AES.new(256, :CBC)
    cipher.encrypt
    cipher.key = $key
    cipher.iv  = iv
    cipher.update(data) << cipher.final
end

def aes_decrypt(iv,data)
    cipher = OpenSSL::Cipher::AES.new(256, :CBC)
    cipher.decrypt
    cipher.key = $key
    cipher.iv  = iv
    data = cipher.update(data) << cipher.final
end

def output_secret()
    file_secret=File.new("./flag","r")
    secret=file_secret.gets
    file_secret.close
    secret_enc=aes_encrypt("A"*16,secret)
    secret_enc_b64=Base64.encode64(secret_enc)
    puts secret_enc_b64 
end

init
banner

server = TCPServer.open 9000
puts "listening on port 9000"
$client = server.accept()


while true do
	begin
		$client.puts "IV:"
		op1 = $client.gets
		iv=Base64.decode64(op1)
		$client.puts "Data:"
		op2 = $client.gets
		data=Base64.decode64(op2)
		data_dec=aes_decrypt iv,data
		$client.puts "Decrpytion Done"
	rescue Exception => e
		$client.puts e.message	
		retry
	end
end
