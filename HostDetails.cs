using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Net.Sockets;
using System.Net;

namespace HostDetails
{
    public class WhoisRecord
    {
        public string Country { get; set; }
        public string Org { get; set; }
        public string raw { get; set; }
    }

    public class DNSRecord
    {
        public String Domain { get; set; }
    }

    class IP
    {
        public static bool IsAddressInSubnet(string address, string subnet, string mask)
        {
            try
            {
                IPAddress Address = IPAddress.Parse(address);
                IPAddress Subnet = IPAddress.Parse(subnet);
                IPAddress Mask = IPAddress.Parse(mask);

                Byte[] addressOctets = Address.GetAddressBytes();
                Byte[] subnetOctets = Mask.GetAddressBytes();
                Byte[] networkOctets = Subnet.GetAddressBytes();

                return
                    ((networkOctets[0] & subnetOctets[0]) == (addressOctets[0] & subnetOctets[0])) &&
                    ((networkOctets[1] & subnetOctets[1]) == (addressOctets[1] & subnetOctets[1])) &&
                    ((networkOctets[2] & subnetOctets[2]) == (addressOctets[2] & subnetOctets[2])) &&
                    ((networkOctets[3] & subnetOctets[3]) == (addressOctets[3] & subnetOctets[3]));
            }
            catch (System.Exception ex)
            {
                return false;
            }
        }
    }

    class Whois
   {

        private const int Whois_Server_Default_PortNumber = 43;
        private const string Whois_Server = "whois.ripe.net";

        private const string Country_Prefix = "country: ";
        private const string Org_Prefix = "org-name: ";

        public WhoisRecord LookupIp(string ipAddress)
        {
            TcpClient whoisClient = null;
            WhoisRecord record;
            List<String> response;

            whoisClient = new TcpClient();
            whoisClient.Connect(Whois_Server, Whois_Server_Default_PortNumber);
            record = new WhoisRecord();
            response = QueryWhois(ipAddress);
            foreach (String line in response)
            {
                if (line.Contains(Country_Prefix))
                {
                    record.Country = line.Replace(Country_Prefix, "");
                }
                if (line.Contains(Org_Prefix))
                {
                    record.Org = line.Replace(Org_Prefix, "");
                }
            }
            record.raw = String.Join("\n\r", response.ToArray());

            whoisClient.Close();

            return record;

        }

        private static List<string> QueryWhois(String ipAddress)
        {
            TcpClient whoisClient = new TcpClient();

            try
            {
                whoisClient.Connect(Whois_Server, Whois_Server_Default_PortNumber);
                string domainQuery = ipAddress + "\n\r";
                byte[] domainQueryBytes = Encoding.ASCII.GetBytes(domainQuery.ToCharArray());


                Stream whoisStream = whoisClient.GetStream();
                whoisStream.Write(domainQueryBytes, 0, domainQueryBytes.Length);

                StreamReader whoisStreamReader = new StreamReader(whoisClient.GetStream(), Encoding.ASCII);

                string streamOutputContent = "";
                List<string> whoisData = new List<string>();

                while (null != (streamOutputContent = whoisStreamReader.ReadLine()))
                {
                    whoisData.Add(streamOutputContent);

                }
                whoisStreamReader.Close();
                whoisClient.Close();

                return whoisData;
            }
            catch (Exception exc)
            {
                System.Console.WriteLine("Connection exception: " + exc.Message);
                return null;
            }
        }
    }
}
