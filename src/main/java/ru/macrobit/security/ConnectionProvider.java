package ru.macrobit.security;

import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class ConnectionProvider {
    private static MongoClient instance;

    private ConnectionProvider() {
    }

    public static MongoClient getConnection(String host, String user,
                                            String pwd, String dbname) {
        if (instance != null)
            return instance;
        List<ServerAddress> seed = new ArrayList<>();
        try {
            seed.add(new ServerAddress(host));
            seed.add(new ServerAddress("c2"));
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
