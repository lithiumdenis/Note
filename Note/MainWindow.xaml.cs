using System;
using System.Text;
using System.Windows;
using System.Windows.Documents;
using Microsoft.Win32;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Windows.Input;

namespace Note
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            ButtonNew.IsEnabled = false;
            ButtonOpen.IsEnabled = false;
            ButtonSave.IsEnabled = false;
            richTextBox.IsEnabled = false;
            RadioRead.IsEnabled = false;
            RadioWrite.IsEnabled = false;
            richTextBox.Document.Blocks.Clear();
            Paragraph par = new Paragraph();
            par.Margin = new Thickness(0); //убираем интервалы
            richTextBox.Document.Blocks.Add(par);
        }
        
		//Пароль для алгоритма шифрования
        private static string internalPass = "yourpass";
		//пароль для начала работы с интерфейсом приложения
        private static string externalPass = "yourpass";
        private static bool KeysEnabled = false;

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.InitialDirectory = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\Notes";
            openFileDialog.Filter = "Note files (*.note)|*.note";
            if (openFileDialog.ShowDialog() == true)
            {
                richTextBox.Document.Blocks.Clear();             
                Paragraph par = new Paragraph(new Run(DecryptText(File.ReadAllText(openFileDialog.FileName, Encoding.UTF8), internalPass)));
                par.Margin = new Thickness(0); //убираем интервалы
                richTextBox.Document.Blocks.Add(par);
            }
        }

        private void ButtonSave_Click(object sender, RoutedEventArgs e)
        {
            saveFunction();
        }

        private void saveFunction()
        {
            string richText = EncryptText(new TextRange(richTextBox.Document.ContentStart, richTextBox.Document.ContentEnd).Text, internalPass);
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Note files (*.note)|*.note";
            saveFileDialog.InitialDirectory = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\Notes";
            saveFileDialog.FileName = DateTime.Now.Year + "-" + DateTime.Now.Month.ToString("d2") + "-" + DateTime.Now.Day.ToString("d2") + " " + DateTime.Now.Hour.ToString("d2") + "." + DateTime.Now.Minute.ToString("d2") + ".note";
            saveFileDialog.FilterIndex = 2;
            saveFileDialog.RestoreDirectory = true;
            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllText(saveFileDialog.FileName, richText);
            }
        }

        private void RadioRead_Click(object sender, RoutedEventArgs e)
        {
            richTextBox.Document.Blocks.Clear();
            ButtonNew.IsEnabled = false;
            ButtonOpen.IsEnabled = true;
            ButtonSave.IsEnabled = false;
        }

        private void RadioWrite_Click(object sender, RoutedEventArgs e)
        {
            ButtonNew.IsEnabled = true;
            ButtonOpen.IsEnabled = false;
            ButtonSave.IsEnabled = true;
        }

        private void ButtonNew_Click(object sender, RoutedEventArgs e)
        {
            richTextBox.Document.Blocks.Clear();
        }

        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 4, 3, 1, 6, 0, 0 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 4, 3, 1, 6, 0, 0 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            return decryptedBytes;
        }

        public string EncryptText(string input, string password)
        {
            // Get the bytes of the string
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);
            string result = Convert.ToBase64String(bytesEncrypted);
            return result;
        }

        public string DecryptText(string input, string password)
        {
            // Get the bytes of the string
            byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);
            string result = Encoding.UTF8.GetString(bytesDecrypted);
            return result;
        }

        private void ButtonPassCheck_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if(MyPasswordBox.Password == externalPass)
                {
                    ButtonNew.IsEnabled = true;
                    ButtonOpen.IsEnabled = false;
                    ButtonSave.IsEnabled = true;
                    richTextBox.IsEnabled = true;
                    RadioRead.IsEnabled = true;
                    RadioWrite.IsEnabled = true;
                    KeysEnabled = true;
                }
                else
                {
                    ButtonNew.IsEnabled = false;
                    ButtonOpen.IsEnabled = false;
                    ButtonSave.IsEnabled = false;
                    richTextBox.IsEnabled = false;
                    RadioRead.IsEnabled = false;
                    RadioWrite.IsEnabled = false;
                    KeysEnabled = false;
                }
            }
            catch
            {
                MessageBox.Show("Неправильный пароль!");
            }
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (KeysEnabled == true)
            {
                if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.S)
                {
                    saveFunction();
                }
            }
        }
    }
}
