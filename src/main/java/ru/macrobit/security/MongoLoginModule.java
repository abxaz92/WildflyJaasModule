package ru.macrobit.security;

import java.net.UnknownHostException;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import com.mongodb.*;

public class MongoLoginModule extends UsernamePasswordLoginModule {
	String userGroup;

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
		super.initialize(subject, callbackHandler, sharedState, options);
	}

	/**
	 * (required) The UsernamePasswordLoginModule modules compares the result of
	 * this method with the actual password.
	 */
	@Override
	protected String getUsersPassword() throws LoginException {
		System.out.format("MyLoginModule: authenticating user '%s'\n", getUsername());
		String password = super.getUsername();
		password = password.toUpperCase();
		return password;
	}

	/**
	 * (optional) Override if you want to change how the password are compared
	 * or if you need to perform some conversion on them.
	 */
	@Override
	protected boolean validatePassword(String inputPassword, String expectedPassword) {

		String encryptedInputPassword = (inputPassword == null) ? null : inputPassword.toUpperCase();
		System.out.format("Validating that (encrypted) input psw '%s' equals to (encrypted) '%s'\n",
				encryptedInputPassword, expectedPassword);
		MongoClient mongoClient = null;
		try {
			List<ServerAddress> seed = new ArrayList<ServerAddress>();
			seed.add(new ServerAddress("db"));
			List<MongoCredential> credentials = new ArrayList<MongoCredential>();
			credentials.add(MongoCredential.createCredential("taxi", "taxi", "Q4862513".toCharArray()));
			mongoClient = new MongoClient(seed, credentials);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		DB db = mongoClient.getDB("taxi");
		DBCollection coll = db.getCollection("user");
		BasicDBObject query = new BasicDBObject("name", getUsername());

		DBCursor cursor = coll.find(query);

		try {
			if (cursor.hasNext()) {
				// User found in DB
				BasicDBObject obj = (BasicDBObject) cursor.next();

				String password = (String) obj.get("password");
				userGroup = (String) obj.get("group");
				if (inputPassword.equals(password)) {
					System.out.println("Password matching");
					return true;
				}
			} else {
				System.out.println("User not found!");
				return false;
			}
		} finally {
			cursor.close();
		}

		return false;
	}

	@Override
	protected Group[] getRoleSets() throws LoginException {
		SimpleGroup group = new SimpleGroup("Roles");
		try {
			// userGroup picked up by MongoDB Cursor earlier
			group.addMember(new SimplePrincipal(userGroup));
		} catch (Exception e) {
			throw new LoginException("Failed to create group member for " + group);
		}
		return new Group[] { group };
	}

}