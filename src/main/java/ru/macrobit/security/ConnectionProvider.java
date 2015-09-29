package ru.macrobit.security;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;

public class ConnectionProvider {
	private static MongoClient instance;

	private ConnectionProvider() {
	}

	public static MongoClient getConnection(String host, String user,
			String pwd, String dbname) {
		if (instance != null)
			return instance;
		List<ServerAddress> seed = new ArrayList<ServerAddress>();
		try {
			seed.add(new ServerAddress(host));
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		List<MongoCredential> credentials = new ArrayList<MongoCredential>();
		credentials.add(MongoCredential.createCredential(user, dbname,
				pwd.toCharArray()));
		instance = new MongoClient(seed, credentials);
		return instance;
	}

}
