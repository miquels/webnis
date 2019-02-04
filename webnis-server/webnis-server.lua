
-- helper function, dprint logs at Log::Level::Debug in rust.
function dprintf(...) dprint(string.format(...)) end

-- example map function. In the example config, this function
-- is called with ("user", "truus") when the client sends a URL like
-- https://servername/.well-known/webnis/<domain>/map/example_map?user=truus
function map_example(key, username)

	-- maps to rust debug! facility
	dprintf("lua map_email: keyname %s, keyval %s", key, username)

	local email

	-- if the username contain a @, look it up in the email
	-- address to username map that we defined in the TOML config
	if string.find(username, "@") ~= nil then
		email = username
		username = nil
		local m = webnis.map_lookup("email2user", "address", email)
		if m ~= nil then
			username = m.username
			dprintf("map_email: mapped %s to %s", email, usernamme)
		else
			dprintf("map_email: %s unknown email", email)
			return nil
		end
	end

	-- now username is syntactically valid
	-- see if it exists in the "passwd" map
	local pwd = webnis.map_lookup("passwd", "name", username)
	if pwd == nil then
		dprintf("map_email: %s user unknown", username)
		return nil
	end

	-- this is the basic reply table, it contains the username and uid
	local ret = { username = username, uid = pwd.uid }

	-- add email address if we have it.
	if email ~= nil then
		ret.email = email
	end

	-- return table. it is served to the user a a JSON object.
	return ret
end

-- authentication. the "auth" table that is passed contains a
-- username and a password.
function auth_example(auth)
	dprintf("auth_xs4all: username [%s]", auth.username)
	local username = auth.username
	local password = auth.password
	local email

	-- auth by email? map to username
	if string.find(username, "@") ~= nil then
		-- map email address to username
		local m = webnis.map_lookup("email2user", "address", email)
		if m == nil then
			dprint("email not found")
			return nil
		end
		email = username
		username = m.username
	end

	-- must have username now
	if username == nil then
		dprint("fatal: username is nil")
		return nil
	end

	-- authenticate
	dprintf("going to auth [%s] [%s] [%s] [x]", "adjunct", "name", username)
	if not webnis.map_auth("adjunct", "name", username, password) then
		dprintf("%s: bad password", username)
		return nil
	end

	dprint("auth ok")
	-- auth OK, build reply.
	if email == nil then
		local m = webnis.map_lookup("email", "user", username)
		if m ~= nil then
			email = m.email
		end
	end

	if email == nil then
		return { username = username }
	else
		return { username = username; email = email }
	end
end

