package ru.macrobit.security;

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
import com.mongodb.DBCursor;
import com.mongodb.DBObject;

public class MongoLoginModule extends UsernamePasswordLoginModule {
	public static final Logger LOG = Logger.getLogger("LoginModule");
	List<ObjectId> userGroup;
	public String database;
	public String username;
	public String password;

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
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
		System.out
				.format("Validating that (encrypted) input psw '%s' equals to (encrypted) '%s'\n",
						encryptedInputPassword, expectedPassword);
		/*
		 * System.out .format(
		 * "Validating that (encrypted) input psw '%s' equals to (encrypted) '%s'\n"
		 * , encryptedInputPassword, expectedPassword);
		 */
		if (inputPassword.equals(doFindUser())) {
			LOG.info(new StringBuilder(expectedPassword).append(
					" success authentificated").toString());
			return true;
		}

		return false;
	}

	private static final String SERVIER_ADDR = "db";
	private static final String PERMISSIONS = "permissions";

	@Override
	protected Group[] getRoleSets() throws LoginException {
		SimpleGroup group = new SimpleGroup("Roles");
		try {
			DB db = ConnectionProvider.getConnection(SERVIER_ADDR, username,
					password, database).getDB(database);
			DBObject query = BasicDBObjectBuilder.start().push("_id")
					.add("$in", userGroup).get();
			DBCursor cursor = null;
			try {
				cursor = db.getCollection(COLLECTION_USERGROUP).find(query);
				while (cursor.hasNext()) {
					// User found in DB
					BasicDBObject obj = (BasicDBObject) cursor.next();
					BasicDBList dbList = (BasicDBList) obj.get(PERMISSIONS);
					if (dbList != null) {
						for (int i = 0; i < dbList.size(); i++) {
							group.addMember(new SimplePrincipal((String) dbList
									.get(i)));
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				cursor.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new LoginException("Failed to create group member for "
					+ group);
		}
		return new Group[] { group };
	}

	private static final String COLLECTION_USER = "user";
	private static final String COLLECTION_USERGROUP = "usergroup";
	private static final String PASSWORD = "password";
	private static final String GROUP_IDS = "groupIds";

	private String doFindUser() {
		String userPassword = null;
		try {
			DB db = ConnectionProvider.getConnection(SERVIER_ADDR, username,
					password, database).getDB(database);
			BasicDBObject query = new BasicDBObject("name", getUsername());
			DBCursor cursor = null;
			try {
				cursor = db.getCollection(COLLECTION_USER).find(query);
				if (cursor.hasNext()) {
					BasicDBObject obj = (BasicDBObject) cursor.next();
					userPassword = (String) obj.get(PASSWORD);
					boolean unlock = obj.getBoolean("unlock");
					if (!unlock)
						throw new LoginException("user account is locked");
					BasicDBList dbList = (BasicDBList) obj.get(GROUP_IDS);
					userGroup = new ArrayList<ObjectId>();
					for (int i = 0; i < dbList.size(); i++) {
						userGroup.add(new ObjectId((String) dbList.get(i)));
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				cursor.close();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return userPassword;
	}

	/*
	 * private DBCollection getCollectionInstance(String collectionName) {
	 * MongoClient mongoClient = null; try { List<ServerAddress> seed = new
	 * ArrayList<ServerAddress>(); seed.add(new ServerAddress("db"));
	 * List<MongoCredential> credentials = new ArrayList<MongoCredential>();
	 * credentials.add(MongoCredential.createCredential(username, database,
	 * password.toCharArray())); mongoClient = new MongoClient(seed,
	 * credentials); } catch (UnknownHostException e) { e.printStackTrace(); }
	 * DB db = mongoClient.getDB(database); DBCollection coll =
	 * db.getCollection(collectionName); return coll; }
	 */
}