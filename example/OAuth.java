package example;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class OAuth {
	static final byte PAD = '=';

	static final short[] _encode_table = {
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
			0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f,
	};

	static final short[] _decode_table = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
			0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
	};

	static int enc(int c)
	{
		return _encode_table[c & 63];
	}

	static int dec(int c)
	{
		return _decode_table[c & 127];
	}

	static byte[] base64_encode(final byte[] src)
	{
		int length = src.length;

		int srcpos, dstlen, dstpos;

		dstlen = (length + 2) / 3 * 4;
		byte[] out = new byte[dstlen];
		if (dstlen > 0) {
			dstpos = 0;
			for (srcpos = 0; srcpos < length; srcpos += 3) {
				int v = (src[srcpos] & 0xff) << 16;
				if (srcpos + 1 < length) {
					v |= (src[srcpos + 1] & 0xff) << 8;
					if (srcpos + 2 < length) {
						v |= src[srcpos + 2] & 0xff;
						out[dstpos + 3] =  (byte)enc(v);
					} else {
						out[dstpos + 3] =  PAD;
					}
					out[dstpos + 2] =  (byte)enc(v >> 6);
				} else {
					out[dstpos + 2] =  PAD;
					out[dstpos + 3] =  PAD;
				}
				out[dstpos + 1] = (byte)enc(v >> 12);
				out[dstpos] =  (byte)enc(v >> 18);
				dstpos += 4;
			}
		}
		return out;
	}

	static byte[] base64_decode(final byte[] src)
	{
		int length = src.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int begin = 0;
		int end = begin + length;
		int ptr = begin;
		int count = 0;
		int bits = 0;
		while (true) {
			if (Character.isSpaceChar(src[ptr])) {
				ptr++;
			} else {
				int c = 0xff;
				if (ptr < end && src[ptr] < 0x80) {
					c = dec(src[ptr]);
				}
				if (c < 0x40) {
					bits = (bits << 6) | c;
					count++;
				} else {
					if (count < 4) {
						bits <<= (4 - count) * 6;
					}
					c = 0xff;
				}
				if (count == 4 || c == 0xff) {
					if (count >= 2) {
						out.write(bits >> 16);
						if (count >= 3) {
							out.write(bits >> 8);
							if (count == 4) {
								out.write(bits);
							}
						}
					}
					count = 0;
					bits = 0;
					if (c == 0xff) {
						break;
					}
				}
				ptr++;
			}
		}
		return out.toByteArray();
	}


	public static byte[] hmac_sha1(byte[] key, byte[] in)
	{
		try {
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

			byte[] tmp;

			byte[] ibuf = new byte[64];
			byte[] obuf = new byte[64];

			for (int i = 0; i < 64; i++) {
				int c = i < key.length ? key[i] : 0;
				ibuf[i] = (byte)(c ^ 0x36);
				obuf[i] = (byte)(c ^ 0x5c);
			}

			sha1.reset();
			sha1.update(ibuf);
			sha1.update(in);
			tmp = sha1.digest();

			sha1.reset();
			sha1.update(obuf);
			sha1.update(tmp);

			return sha1.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String sign_hmac_sha1(String m, String k)
	{
		try {
			byte[] key;
			byte[] result;

			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			sha1.update(k.getBytes());
			key = sha1.digest();

			result = hmac_sha1(key, m.getBytes());
			byte[] b = base64_encode(result);
			return new String(b, "UTF-8");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static final char[] hextable = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	public static byte[] url_encode(byte[] in)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int pos = 0;
		while (pos < in.length) {
			int c = in[pos] & 0xff;
			pos++;
			if (Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '-' || c == '~') {
				out.write(c);
			} else {
				out.write('%');
				out.write(hextable[(c >> 4) & 0x0f]);
				out.write(hextable[c & 0x0f]);
			}
		}
		return out.toByteArray();
	}

	private static int hextoint(char c)
	{
		c = Character.toUpperCase(c);
		if (c >= '0' && c <= '9') {
			return (int)c - (int)'0';
		}
		if (c >= 'A' && c <= 'F') {
			return (int)c - (int)'A' + 10;
		}
		return -1;
	}

	private static boolean isxdigit(int c)
	{
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	}

	public static byte[] url_decode(byte[] in)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int pos = 0;
		while (pos < in.length) {
			int c = in[pos] & 0xff;
			pos++;
			if (c == '+') {
				c = ' ';
			} else if (c == '%' && isxdigit(in[pos] & 0xff) && isxdigit(in[pos + 1] & 0xff)) {
				char hi = (char)(in[pos] & 0xff);
				char lo = (char)(in[pos + 1] & 0xff);
				hi = Character.toUpperCase(hi);
				lo = Character.toUpperCase(lo);
				c = (hextoint(hi) << 4) | hextoint(lo);
				pos += 2;
			}
			out.write(c);
		}
		return out.toByteArray();
	}

	static long time()
	{
		return System.currentTimeMillis() / 1000;
	}

	static String noncechars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

	static String nonce()
	{
		StringBuilder sb = new StringBuilder();
		Random rand = new Random(time());
		final int max = 26 + 26 + 10 + 1;
		int len = 15 + rand.nextInt() % 16;
		for (int i = 0; i < len; i++) {
			char c = noncechars.charAt(rand.nextInt(max));
			sb.append(c);
		}
		return sb.toString();
	}

	static boolean key_in_strings(String key, List<String> list)
	{
		int keylen = key.length();
		for (String str : list) {
			if (str.length() > keylen && str.startsWith(key) && str.charAt(keylen) == '=') {
				return true;
			}
		}
		return false;
	}

	public static class Keys {
		public String consumer_key;
		public String consumer_sec;
		public String accesstoken;
		public String accesstoken_sec;
	}

	static boolean isEmpty(String s)
	{
		if (s == null) return true;
		if (s.length() < 1) return true;
		return false;
	}

	static String build(List<String> vec)
	{
		StringBuilder sb = new StringBuilder();
		for (String s : vec) {
			if (sb.length() > 0) {
				sb.append('&');
			}
			int i = s.indexOf('=');
			if (i > 0) {
				String k = s.substring(0, i);
				String v = s.substring(i + 1);
				sb.append(k);
				sb.append('=');
				sb.append(new String(url_encode(v.getBytes())));
			}
		}
		return sb.toString();
	}

	boolean post(ArrayList<String> vec)
	{
		try {
			String oauth_nonce = "oauth_nonce";
			if (!key_in_strings(oauth_nonce, vec)) {
				oauth_nonce += '=';
				oauth_nonce += nonce();
				vec.add(oauth_nonce);
			}

			String oauth_timestamp = "oauth_timestamp";
			if (!key_in_strings(oauth_timestamp, vec)) {
				oauth_timestamp += '=';
				oauth_timestamp += Long.toString(time());
				vec.add(oauth_timestamp);
			}

			if (!isEmpty(keys.accesstoken)) {
				String oauth_token = "oauth_token";
				oauth_token += '=';
				oauth_token += keys.accesstoken;
				vec.add(oauth_token);
			}

			String oauth_consumer_key = "oauth_consumer_key";
			oauth_consumer_key += '=';
			oauth_consumer_key += keys.consumer_key;
			vec.add(oauth_consumer_key);

			String oauth_signature_method = "oauth_signature_method";
			oauth_signature_method += '=';
			oauth_signature_method += "HMAC-SHA1";
			vec.add(oauth_signature_method);

			String oauth_version = "oauth_version";
			if (!key_in_strings(oauth_version, vec)) {
				oauth_version += '=';
				oauth_version += "1.0";
				vec.add(oauth_version);
			}

			Collections.sort(vec);

			String query = build(vec);

			String url = "https://api.twitter.com/1.1/statuses/update.json";
			String httpmethod = "POST";

			{
				String m = httpmethod + '&' + new String(url_encode(url.getBytes()), "UTF-8") + '&' + new String(url_encode(query.getBytes()));
				String k = keys.consumer_sec + '&' + keys.accesstoken_sec;
				String oauth_signature = "oauth_signature=" + sign_hmac_sha1(m, k);
				vec.add(oauth_signature);
			}

			String posttext = build(vec);
			byte[] postdata = posttext.getBytes();

			URI uri = new URI(url);
			HttpsURLConnection con = (HttpsURLConnection)uri.toURL().openConnection();
			con.setDoInput(true);
			con.setDoOutput(true);
			con.setUseCaches(false);
			con.setChunkedStreamingMode(0);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			con.setRequestProperty("Content-Length", Integer.toString(postdata.length));
			con.setRequestProperty("User-Agent", "Example");
			con.setRequestProperty("Connection", "Close");
			OutputStream o = con.getOutputStream();
			o.write(postdata);
			o.flush();
			o.close();

			int rc = con.getResponseCode();
			if (rc == HttpsURLConnection.HTTP_OK) {
				StringBuilder sb = new StringBuilder();
				BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
				while (true) {
					String line = br.readLine();
					if (line == null) break;
					sb.append(line);
				}
				return true;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return false;
	}


	Keys keys;

	public OAuth(Keys k)
	{
		keys = k;
	}
}
