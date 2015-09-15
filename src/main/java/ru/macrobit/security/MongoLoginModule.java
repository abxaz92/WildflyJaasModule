package ru.macrobit.security;

import java.net.UnknownHostException;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.bson.types.ObjectId;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.BasicDBObjectBuilder;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;

public class MongoLoginModule extends UsernamePasswordLoginModule {
	public static final Logger LOG = Logger.getLogger("LoginModule");
	java.util.List<ObjectId> userGroup;
	java.lang.String database;
	java.lang.String username;
	java.lang.String password;

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String,?> sharedState, Map<String,?> options) {
		super.initialize(subject, callbackHandler, sharedState, options);
		database = (String) options.get("database");
		username = (String) options.get("username");
		password = (String) options.get("password");
	}

	/**
	 * (required) The UsernamePasswordLoginModule modules compares the result of
	 * this method with the actual password.
	 */
	@Override
	protected String getUsersPassword() throws LoginException {
		String password = super.getUsername();
		password = password.toUpperCase();
		return password;
	}

	/**
	 * (optional) Override if you want to change how the password are compared
	 * or if you need to perform some conversion on them.
	 */
	@Override
	protected boolean validatePassword(String inputPassword,
			String expectedPassword) {

		String encryptedInputPassword = (inputPassword == null) ? null
				: inputPassword.toUpperCase();
		BasicDBObject query = new BasicDBObject("name", getUsername());
		DBCursor cursor = getCollectionInstance("user").find(query);
		System.out
				.format("Validating that (encrypted) input psw '%s' equals to (encrypted) '%s'\n",
						encryptedInputPassword, expectedPassword);
		try {
			if (cursor.hasNext()) {
				BasicDBObject obj = (BasicDBObject) cursor.next();
				String password = (String) obj.get("password");
				boolean unlock = obj.getBoolean("unlock");
				if(!unlock)
					throw new LoginException("user account is locked");
					
				BasicDBList dbList = (BasicDBList) obj.get("groupIds");
				userGroup = new ArrayList<ObjectId>();
				for (int i = 0; i < dbList.size(); i++) {
					userGroup.add(new ObjectId((String) dbList.get(i)));
				}
				if (inputPassword.equals(password)) {
					LOG.info("Password matching");
					return true;
				}
			} else {
				LOG.info("User not found!");
				return false;
			}

		} catch (Exception e) {
			e.printStackTrace();
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
			DBObject query = BasicDBObjectBuilder.start().push("_id")
					.add("$in", userGroup).get();
			DBCursor cursor = getCollectionInstance("usergroup").find(query);
			try {
				while (cursor.hasNext()) {
					// User found in DB
					BasicDBObject obj = (BasicDBObject) cursor.next();
					BasicDBList dbList = (BasicDBList) obj.get("permissions");
					if (dbList != null) {
						for (int i = 0; i < dbList.size(); i++) {
							group.addMember(new SimplePrincipal((String) dbList
									.get(i)));
						}
					}
				}
			} catch (Exception e) {
				LOG.info(e.getMessage());
			} finally {
				cursor.close();
			}

			// group.addMember(new SimplePrincipal(userGroup));
		} catch (Exception e) {
			throw new LoginException("Failed to create group member for "
					+ group);
		}
		return new Group[] { group };
	}

	private DBCollection getCollectionInstance(String collectionName) {
		MongoClient mongoClient = null;
		try {
			List<ServerAddress> seed = new ArrayList<ServerAddress>();
			seed.add(new ServerAddress("db"));
			List<MongoCredential> credentials = new ArrayList<MongoCredential>();
			credentials.add(MongoCredential.createCredential(username,
					database, password.toCharArray()));
			mongoClient = new MongoClient(seed, credentials);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		DB db = mongoClient.getDB(database);
		DBCollection coll = db.getCollection(collectionName);
		return coll;
	}
}