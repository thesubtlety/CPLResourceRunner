// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe .\encrypt.cs
// encrypt.exe shell.bin "Key"

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.IO.Compression;

namespace Cryptor
{
    class Program
    {
        public const int KEY_SIZE = 16;

       static byte[] Decrypt(string password, byte[] encryptedBytes)
        {

            var sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
            var hash = sha256CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(password));
            var key = new byte[KEY_SIZE];
            var iv = new byte[KEY_SIZE];

            Buffer.BlockCopy(hash, 0, key, 0, KEY_SIZE);
            Buffer.BlockCopy(hash, KEY_SIZE, iv, 0, KEY_SIZE);

            using (var cipher = new AesCryptoServiceProvider().CreateDecryptor(key, iv))
            using (var source = new MemoryStream(encryptedBytes))
            using (var output = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(source, cipher, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(output);
                }
                return output.ToArray();
            }
        }

        public static byte[] Encrypt (string password, byte[] input)
        {
            var sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
            var hash = sha256CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(password));
            var key = new byte[KEY_SIZE];
            var iv = new byte[KEY_SIZE];

            Buffer.BlockCopy(hash, 0, key, 0, KEY_SIZE);
            Buffer.BlockCopy(hash, KEY_SIZE, iv, 0, KEY_SIZE);

            using (var cipher = new AesCryptoServiceProvider().CreateEncryptor(key, iv))
            using (var output = new MemoryStream())                
            {                
                using (var cryptoStream = new CryptoStream(output, cipher, CryptoStreamMode.Write))
                {
                    //var inputBytes = Encoding.UTF8.GetBytes(input);   
                    var inputBytes = input;
                    cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                }
                return output.ToArray();
            }
        }


    public static byte[] Decompress(byte[] input)
    {
        using (var source = new MemoryStream(input))
        {
            byte[] lengthBytes = new byte[4];
            source.Read(lengthBytes, 0, 4);

            var length = BitConverter.ToInt32(lengthBytes, 0);
            using (var decompressionStream = new GZipStream(source,
                CompressionMode.Decompress))
            {
                var result = new byte[length];
                decompressionStream.Read(result, 0, length);
                return result;
            }
        }
    }

        public static byte[] Compress(byte[] input)
        {
            using (var result = new MemoryStream())
            {
                var lengthBytes = BitConverter.GetBytes(input.Length);
                result.Write(lengthBytes, 0, 4);

                using (var compressionStream = new GZipStream(result,
                    CompressionMode.Compress))
                {
                    compressionStream.Write(input, 0, input.Length);
                    compressionStream.Flush();

                }
                return result.ToArray();
            }
        }


        static void Usage()
        {
            string usageString = @"
.\crypt.exe shellcode.bin pass
Encrypt, compress, print base64 bin to txt
";
            Console.WriteLine(usageString);
        }

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Usage();
                Environment.Exit(1);
            }
            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Could not find path to shellcode bin file: {0}", args[0]);
                Environment.Exit(1);
            }
            byte[] shellcodeBytes = File.ReadAllBytes(args[0]);
            string pass = args[1];
            byte[] encShellcodeBytes = Encrypt(pass, shellcodeBytes);
            byte[] compressed = Compress(encShellcodeBytes);
            string b64 = Convert.ToBase64String(compressed);
            File.WriteAllBytes("encrypted.txt",  Encoding.ASCII.GetBytes(b64));
            Console.WriteLine(b64);
            Console.WriteLine("Wrote encoded binary to encrypted.txt.");
        }
    }
}
