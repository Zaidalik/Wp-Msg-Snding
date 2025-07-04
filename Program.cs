using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

class WpMsgSnder
{
    static async Task Main(string[] args)
    {
        /*payload will like this
        {
            "id": 123456789,
            "email": "customer@example.com",
            "phone": "+923321234567",
            "created_at": "2025-05-20T12:00:00Z",
            "total_price": "5999.00",
            "line_items": [
              {
                          "title": "Blue T-Shirt",
                "quantity": 1
              }
            ]
        }           */


        // 👇 JSON payload with full order
        var json = @"
        {
          ""number"": ""923311346979"",
          ""order"": {
            ""id"": 123456789,
            ""email"": ""customer@example.com"",
            ""phone"": ""+923460896384"",
            ""created_at"": ""2025-05-20T12:00:00Z"",
            ""total_price"": ""5999.00"",
            ""line_items"": [
              {
                ""title"": ""Blue T-Shirt"",
                ""quantity"": 1
              },
              {
                ""title"": ""Black Jeans"",
                ""quantity"": 2
              }
            ]
          }
        }";

        using (HttpClient client = new HttpClient())
        {
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync("http://localhost:3000/send", content);
            string result = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"Response: {result}");
        }
    }
}
