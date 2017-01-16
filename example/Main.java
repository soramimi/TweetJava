package example;


import java.io.IOException;
import java.util.ArrayList;


public class Main {

	static class Twitter extends OAuth {
		public Twitter(Keys k)
		{
			super(k);
		}

		public boolean tweet(String text)
		{
			ArrayList<String> vec = new ArrayList<>();
			vec.add("status=" + text);
			return post(vec);
		}
	}


	public static void main(String[] args) throws IOException
	{
		OAuth.Keys keys = new OAuth.Keys();
		keys.consumer_key    = "xxxxxxxxxxxxxxxxxxxxxx";
		keys.consumer_sec    = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
		keys.accesstoken     = "0000000000-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
		keys.accesstoken_sec = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
		String text = "Hello, world";
		Twitter twitter = new Twitter(keys);
		twitter.tweet(text);
	}
}
