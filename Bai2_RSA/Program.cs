using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA
{
    class Program
    {
        static RSA rsa = RSA.Create(2048);

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("\n===== RSA Benchmark & Management =====");
                Console.WriteLine("1. Sinh cap khoa RSA (2048-bit) va xuat ra public.pem / private.pem");
                Console.WriteLine("2. Ma hoa / Giai ma van ban mau");
                Console.WriteLine("3. Do toc do RSA (Benchmark)");
                Console.WriteLine("4. Thong ke SHA-256");
                Console.WriteLine("0. Thoat");
                Console.Write("Chon chuc nang: ");

                string choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        SinhVaLuuKhoa();
                        break;
                    case "2":
                        ThuNghiemMaHoa();
                        break;
                    case "3":
                        DoHieuNangRSA();
                        break;
                    case "4":
                        ThongKeSHA256();
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Lua chon khong hop le.");
                        break;
                }
            }
        }

        static void SinhVaLuuKhoa()
        {
            rsa = RSA.Create(2048);

            // Xuat khoa cong khai ra public.pem
            string publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
            File.WriteAllText("public.pem", publicKeyPem);
            Console.WriteLine("Da tao va ghi: public.pem");

            // Xuat khoa bi mat ra private.pem
            string privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
            File.WriteAllText("private.pem", privateKeyPem);
            Console.WriteLine("Da tao va ghi: private.pem");
        }

        static void ThuNghiemMaHoa()
        {
            Console.Write("Nhap chuoi van ban can ma hoa: ");
            string plainText = Console.ReadLine() ?? "";
            byte[] data = Encoding.UTF8.GetBytes(plainText);

            byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            Console.WriteLine($"Ban ma (Base64): {Convert.ToBase64String(cipher)}");

            byte[] decrypted = rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            Console.WriteLine($"Giai ma nguoc lai: {Encoding.UTF8.GetString(decrypted)}");
        }

        static void DoHieuNangRSA()
        {
            // Cho sua 1 theo yeu cau bai tap
            int ne = 1000, nd = 100;
            byte[] data = new byte[32];
            RandomNumberGenerator.Fill(data);

            Console.WriteLine($"Dang do ma hoa ({ne} lan) va giai ma ({nd} lan)...");

            Stopwatch sw = Stopwatch.StartNew();
            byte[] cipher = null;
            for (int i = 0; i < ne; i++)
            {
                cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
            sw.Stop();
            double timeEnc = sw.Elapsed.TotalMilliseconds;
            Console.WriteLine($"Ma hoa: {ne} lan het {timeEnc:F2} ms (trung binh {timeEnc / ne:F4} ms/lan)");

            sw.Restart();
            for (int i = 0; i < nd; i++)
            {
                rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            }
            sw.Stop();
            double timeDec = sw.Elapsed.TotalMilliseconds;
            Console.WriteLine($"Giai ma: {nd} lan het {timeDec:F2} ms (trung binh {timeDec / nd:F4} ms/lan)");
        }

        static void ThongKeSHA256()
        {
            // Cho sua 2 theo yeu cau bai tap
            int total = 0, N = 5000;
            Console.WriteLine($"Dang tinh toan SHA-256 voi so mau N = {N}...");
        }
    }
}