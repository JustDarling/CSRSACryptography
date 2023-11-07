using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

RsaEncryption rsa = new RsaEncryption();
string cypher = string.Empty;

Console.WriteLine($"Public Key: {rsa.GetPublicKey()} \n");

Console.WriteLine("Enter you text to encrypt");
var text = Console.ReadLine();
if (!string.IsNullOrEmpty(text))
{
    cypher = rsa.Encrypt(text);
    Console.WriteLine($"Encrypted text: {cypher}");
}

Console.WriteLine("Press any key to decrypt text");
Console.ReadLine();  
var plainText = rsa.Decrypt(cypher);

Console.WriteLine($"Decrypted text: {plainText}");
Console.ReadLine();

public class RsaEncryption
{
    private static RSACryptoServiceProvider  csp = new RSACryptoServiceProvider (2048);
    private RSAParameters _privatekey;
    private RSAParameters _publickey;

    public RsaEncryption()
    {
        _privatekey = csp.ExportParameters(true);
        _publickey = csp.ExportParameters(false);
    }

    public string GetPublicKey()
    {
        var sw = new StringWriter();
        var xs = new XmlSerializer(typeof(RSAParameters));
        xs.Serialize(sw, _publickey);
        return sw.ToString();
    }

    public string Encrypt(string plainText)
    {
        csp = new RSACryptoServiceProvider();
        csp.ImportParameters(_publickey);
        var data = Encoding.Unicode.GetBytes(plainText);
        var cypher = csp.Encrypt(data, false);
        return Convert.ToBase64String(cypher);
    }

    public string Decrypt(string cypherText)
    {
        var dataBytes = Convert.FromBase64String(cypherText);
        csp.ImportParameters(_privatekey);
        var plainText = csp.Decrypt(dataBytes, false);
        return Encoding.Unicode.GetString(plainText);
    }
}