// See https://aka.ms/new-console-template for more information

using System.Diagnostics;

Debug.WriteLine("Testing .NET Standard 2.0 DLL from .NET 7 Console App !");

var masterCode = @"{2A517BA1-9DA5-4259-AE1D-711B2571B415}";
var enc = new Encryption.Encryptor();
var encryptedPassword = enc.EncryptPassword("jk", masterCode);

Debug.WriteLine("encryptedPassword = " + encryptedPassword);

var decryptedPassword = enc.DecryptPassword(@"QSqhu8o/t8MFRA0XNjGrfg==", masterCode);
Debug.WriteLine("decryptedPassword = " + decryptedPassword);

