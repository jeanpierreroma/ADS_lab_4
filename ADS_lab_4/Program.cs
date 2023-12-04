using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class RSACSPSample
{
    private const string DefaultRoutePlainTextFile = "D:\\University\\7_term\\Application and data security\\Labs\\Labs\\Lab_4\\TestFolder\\PlainText\\";
    private const string DefaultRouteEncryptedFile = "D:\\University\\7_term\\Application and data security\\Labs\\Labs\\Lab_4\\TestFolder\\CryptedText\\";
    private const string DefaultRouteDecryptedFile = "D:\\University\\7_term\\Application and data security\\Labs\\Labs\\Lab_4\\TestFolder\\DecryptedText\\";

    static void Main()
    {
        const string fileName = "text_1.txt";

        // Зчитуємо дані для шифрування
        byte[] plainText = ReadTextFile(fileName);
        Console.WriteLine("Data was readed from file");

        using (RSACng rsa = new RSACng())
        {
            RSAParameters publicKey = rsa.ExportParameters(true);

            //Шифрування
            Stopwatch rsaEcryptTime = new Stopwatch();
            rsaEcryptTime.Start();

            byte[] encryptedData = RSAEncryptAlgorithm(plainText, publicKey);

            rsaEcryptTime.Stop();

            WriteByteFile($"encrypted_{fileName}", encryptedData);
            Console.WriteLine($"Data was crypted into folder, time: {rsaEcryptTime.Elapsed}");

            //Розшифрування
            byte[] dataToDecrypt = ReadByteFile($"encrypted_{fileName}");

            Stopwatch rsaDecryptTime = new Stopwatch();
            rsaDecryptTime.Start();

            string decryptedText = RSADecryptAlgorithm(dataToDecrypt, publicKey);

            rsaDecryptTime.Stop();
            Console.WriteLine($"Data was decrypted into file, time: {rsaDecryptTime.Elapsed}");

            WriteTextFile(fileName, decryptedText);
        }

    }

    public static byte[][] SplitDataIntoBlocks(byte[] data, int blockSize)
    {
        int blockCount = (int)Math.Ceiling((double)data.Length / blockSize);
        byte[][] blocks = new byte[blockCount][];

        for (int i = 0; i < blockCount; i++)
        {
            int startIndex = i * blockSize;
            int length = Math.Min(blockSize, data.Length - startIndex);

            blocks[i] = new byte[length];
            Array.Copy(data, startIndex, blocks[i], 0, length);
        }

        return blocks;
    }

    public static void Encrypt(byte[] data, out byte[] encryptedData, RSAParameters RSAKeyInfo, bool isLast)
    {
        RSAEncryptionPadding pad = isLast ? RSAEncryptionPadding.Pkcs1 : null;
        
        encryptedData = RSAEncrypt(data, RSAKeyInfo, pad);
    }

    public static void Decrypt(byte[] encryptedData, out byte[] decryptedData, RSAParameters RSAKeyInfo, bool isLast)
    {
        RSAEncryptionPadding pad = isLast ? RSAEncryptionPadding.Pkcs1 : null;

        decryptedData = RSADecrypt(encryptedData, RSAKeyInfo, pad);
    }

    public static byte[] RSAEncrypt(byte[] dataToEncrypt, RSAParameters RSAKeyInfo, RSAEncryptionPadding pad)
    {
        byte[] encryptedData = null;

        using (RSACng RSA = new RSACng())
        {
            RSA.ImportParameters(RSAKeyInfo);

            encryptedData = RSA.Encrypt(dataToEncrypt, pad);
        }
        return encryptedData;
    }

    public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, RSAEncryptionPadding pad)
    {
        byte[] decryptedData = null;

        using (RSACng RSA = new RSACng())
        {
            RSA.ImportParameters(RSAKeyInfo);

            decryptedData = RSA.Decrypt(DataToDecrypt, pad);
        }

        return decryptedData;
    }

    public static byte[] RSAEncryptAlgorithm(byte[] plainText, RSAParameters publicKey)
    {
        // Розбивка даних на блоки
        int blockSize = 128;
        int blockCypherFile = 256;

        byte[][] dataToEncrypt = SplitDataIntoBlocks(plainText, blockSize);

        // Шифрування кожного блоку окремо
        byte[] encryptData = new byte[dataToEncrypt.Length * blockCypherFile];
        for (int i = 0; i < dataToEncrypt.Length; i++)
        {
            Encrypt(dataToEncrypt[i], out byte[] encryptedData, publicKey, true);

            Array.Copy(encryptedData, 0, encryptData, i * blockCypherFile, encryptedData.Length);
        }

        return encryptData;

    }
    public static string RSADecryptAlgorithm(byte[] encryptedData, RSAParameters publicKey)
    {
        int blockSize = 256;

        StringBuilder decryptedText = new StringBuilder();

        byte[][] dataToDecrypt = SplitDataIntoBlocks(encryptedData, blockSize);

        for (int i = 0; i < dataToDecrypt.Length; i++)
        {
            Decrypt(dataToDecrypt[i], out byte[] decryptData, publicKey, true);

            decryptedText.Append(Encoding.UTF8.GetString(decryptData));
        }

        return decryptedText.ToString();
    }

    public static byte[] ReadTextFile(string fileName)
    {
        byte[] plainText = null;
        
        string filePath = DefaultRoutePlainTextFile + fileName;

        try
        {
            string fileText = File.ReadAllText(filePath);

            if (fileText == null || fileText.Length == 0)
            {
                throw new ArgumentException("Empty file error");
            }

            plainText = Encoding.UTF8.GetBytes(fileText);
        }
        catch (FileNotFoundException)
        {
            throw new FileNotFoundException(filePath);
        }

        return plainText;
    }
    public static byte[] ReadByteFile(string fileName)
    {
        byte[] plainText = null;

        string filePath = DefaultRouteEncryptedFile + fileName;

        try
        {
            plainText = File.ReadAllBytes(filePath);
        }
        catch (FileNotFoundException)
        {
            throw new FileNotFoundException(filePath);
        }

        return plainText;
    }
    public static void WriteByteFile(string fileName, byte[] plainText)
    {
        string filePath = DefaultRouteEncryptedFile + fileName;

        try
        {
            File.WriteAllBytes(filePath, plainText);
        }
        catch (DirectoryNotFoundException)
        {
            throw new DirectoryNotFoundException(filePath);
        }
    }
    public static void WriteTextFile(string fileName, string text)
    {
        string filePath = DefaultRouteDecryptedFile + fileName;

        File.WriteAllText(filePath, text);
    }
}
