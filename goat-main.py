import requests, tls_client, random, names, uuid, json, time, random_address, socket, struct, datetime
from multiprocessing.dummy import Pool as ThreadPool

proxyList = []

def loadProxies():
    proxies = open("proxies-dc.txt").read().splitlines()
    for proxy in proxies:
        try:
            if len(proxy.split(":")) == 2:
                ip = proxy.split(":")[0]
                port = proxy.split(":")[1]
                proxyData = {
                    "http": "http://{}:{}".format(ip, port),
                    "https": "http://{}:{}".format(ip, port),
                }
                proxyList.append(proxyData)
            else:
                ip = proxy.split(":")[0]
                port = proxy.split(":")[1]
                user = proxy.split(":")[2]
                password = proxy.split(":")[3]
                proxyData = {
                    "http": "http://{}:{}@{}:{}".format(user, password, ip, port),
                    "https": "http://{}:{}@{}:{}".format(user, password, ip, port),
                }
                proxyList.append(proxyData)
        except:
            pass

try:
    loadProxies()
except:
    pass

def getAddress():
    getAddress = False
    while getAddress == False:
        try:
            listState = ["CT", "MA", "VT", "AL", "AR", "FL", "GA", "KY", "MD", "OK", "TN", "TX", "AZ", "CA", "CO"]
            stateSelected = random.choice(listState)
            addressCheckout = random_address.real_random_address_by_state(stateSelected)

            # Convert state to full name
            stateDetails = {
                'CT': 'Connecticut',
                'MA': 'Massachusetts',
                'VT': 'Vermont',
                'AL': 'Alabama',
                'AR': 'Arkansas',
                'FL': 'Florida',
                'GA': 'Georgia',
                'KY': 'Kentucky',
                'MD': 'Maryland',
                'OK': 'Oklahoma',
                'TN': 'Tennessee',
                'TX': 'Texas',
                'AZ': 'Arizona',
                'CA': 'California',
                'CO': 'Colorado',
            }

            stateSelected = stateDetails[stateSelected]

            address = addressCheckout["address1"]
            zipCode = addressCheckout["postalCode"]
            address2 = addressCheckout["address2"]
            city = addressCheckout["city"]
            getAddress = True
        except Exception as e:
            continue
    return address, address2, city, zipCode, stateSelected

def onboarding(session, authToken):
    headers = {
        'Host': 'www.goat.com',
        'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
        'Accept': 'application/json',
        'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
        'Authorization': f'Token token="{authToken}"',
        'Accept-Language': 'en-GB,en;q=0.9',
        #'x-emb-st': '1700396816373',
        'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
        #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = {"campaign":2}
    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://www.goat.com/api/v1/community_users/accept-terms', headers=headers, json=data, insecure_skip_verify=True)
            if response.status_code < 310:
                print(f"Successfully accepted terms for {authToken}")
                timeOut = True
            else:
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except:
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)

    data = {"locationCoordinates":{"longitude":0.04232195966376997,"latitude":51.458576561974255},"countryCode":"GB"}

    timeOut = False
    while timeOut == False:
        try:
            response = session.post(
                'https://www.goat.com/api/v1/consumer-segment-access/validate-verified-location',
                headers=headers,
                json=data, 
                insecure_skip_verify=True
            )
            if response.status_code < 310:
                print(f"Successfully validated location for {authToken}")
                timeOut = True
            else:
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except:
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)


    data = {"city":"London","country":"GB","state":"England"}

    timeOut = False
    while timeOut == False:
        try:
            response = session.post(
                'https://www.goat.com/api/v1/community_users/update-user-profile',
                headers=headers,
                json=data,
                insecure_skip_verify=True
            )
            if response.status_code < 310:
                print(f"Successfully updated user profile for {authToken}")
                timeOut = True
            else:
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except:
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)

    data = {"campaign":2}

    timeOut = False
    while timeOut == False:
        try:
            response = session.post(
                'https://www.goat.com/api/v1/community_users/complete-onboarding',
                headers=headers,
                json=data,
                insecure_skip_verify=True
            )
            if response.status_code < 310:
                print(f"Successfully completed onboarding for {authToken}")
                timeOut = True
            else:
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except:
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    
    return session

def get_tickets(session, authToken):
    headers = {
        'Host': 'www.goat.com',
        'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
        'Accept': 'application/json',
        'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
        'Authorization': f'Token token="{authToken}"',
        'Accept-Language': 'en-GB,en;q=0.9',
        #'x-emb-st': '1700396816373',
        'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
        #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {"status":2}

    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://www.goat.com/api/v1/achievement_tickets/get-count', headers=headers, json=data, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()
                count = response["count"]
                timeOut = True
            else:
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except Exception as e:
            print(f"Error getting tickets for {authToken}: {e}")
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    
    return count

def unlocking_drop(session, authToken, dropId):
    headers = {
        'Host': 'www.goat.com',
        'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
        'Accept': 'application/json',
        'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
        'Authorization': f'Token token="{authToken}"',
        'Accept-Language': 'en-GB,en;q=0.9',
        #'x-emb-st': '1700396816373',
        'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
        #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {"dropId":dropId}

    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://www.goat.com/api/v1/drops/unlock-drop-tickets', headers=headers, json=data, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()
                print(response)
                timeOut = True
            else:
                print(response)
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except Exception as e:
            print(f"Error getting tickets for {authToken}: {e}")
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)

    ticketsUnlocked = response["data"]["ticketsUnlocked"]
    if ticketsUnlocked == True:
        productId = response["data"]["id"]
        priceCents = response["data"]["priceCents"]
        print(f"Successfully unlocked tickets for {authToken}")
        return session, productId, priceCents
    else:
        print(f"Failed to unlock tickets for {authToken}")
        return session, None, None

def generate_account(session):
    while True:
        time.sleep(random.randint(0,10))
        try:
            timeOut = False
            while timeOut == False:
                try:
                    listBypassReason = [{"reason": "Error checking sdk enabled - general failure", "authorisation": "4"}, {"reason":'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.', "authorisation": f'3:{uuid.uuid4()}'}]
                    selectedBypassReason = random.choice(listBypassReason)
                    randomIp = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                    listIosVer = ["17.0.3", "17.0.1", "17.0.2", "17.0", "16.0", "16.1", "16.2", "16.3", "16.4", "15.1", "15.0", "15.2", "15.3"]
                    randomEmbedId = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
                    headers = {
                        'Host': 'www.goat.com',
                        'X-PX-AUTHORIZATION': selectedBypassReason["authorisation"],
                        'Accept': 'application/json',
                        'X-PX-BYPASS-REASON': selectedBypassReason["reason"],
                        'Authorization': f'Token token=""',
                        'Accept-Language': 'en-GB,en;q=0.9',
                        'x-emb-st': str(int(time.time() * 1000)),
                        'User-Agent': f'GOAT/2.66.2 (iPhone; iOS {random.choice(listIosVer)}; Scale/3.00) Locale/en',
                        'x-emb-id': randomEmbedId,
                        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Forwarded-For': randomIp,
                    }
                    firstName = names.get_first_name()
                    lastName = names.get_last_name()
                    email = firstName.lower() + lastName.lower() + str(random.randint(100000, 99999999)) + "@obdmail.com"
                    data = {
                        'emailRegistration': '1',
                        'user[password]': 'Abcd1234!!!',
                        'user[email]': email,
                        'user[name]': f'{firstName} {lastName}',
                        'user[region]': 'US',
                    }
                    response = session.post('https://www.goat.com/api/v1/users', headers=headers, data=data, insecure_skip_verify=True)
                    if response.status_code < 310:
                        response = response.json()
                        userId = response["id"]
                        username = response["username"]
                        authToken = response["authToken"]
                        print(f"Successfully created user account: {email}")
                        timeOut = True
                    else:
                        print(response.text)
                        chromeClient = ["Chrome116", "Chrome117", "Chrome118", "Chrome115"]
                        session = tls_client.Session(client_identifier=random.choice(chromeClient))
                        if len(proxyList) > 0:
                            session.proxies = random.choice(proxyList)
                        time.sleep(random.randint(0,4))
                except Exception as e:
                    print(f"Error creating user account: {e}")
                    if len(proxyList) > 0:
                        session.proxies = random.choice(proxyList)

            return session, email, userId, username, authToken
        except:
            pass

def login(session, email):
    timeOut = False
    while timeOut == False:
        try:
            listBypassReason = [{"reason": "Error checking sdk enabled - general failure", "authorisation": "4"}, {"reason":'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.', "authorisation": f'3:{uuid.uuid4()}'}]
            selectedBypassReason = random.choice(listBypassReason)
            randomIp = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
            listIosVer = ["17.0.3", "17.0.1", "17.0.2", "17.0", "16.0", "16.1", "16.2", "16.3", "16.4", "15.1", "15.0", "15.2", "15.3"]
            randomEmbedId = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
            headers = {
                'Host': 'www.goat.com',
                'X-PX-AUTHORIZATION': selectedBypassReason["authorisation"],
                'Accept': 'application/json',
                'X-PX-BYPASS-REASON': selectedBypassReason["reason"],
                'Authorization': f'Token token=""',
                'Accept-Language': 'en-GB,en;q=0.9',
                'x-emb-st': str(int(time.time() * 1000)),
                'User-Agent': f'GOAT/2.66.2 (iPhone; iOS {random.choice(listIosVer)}; Scale/3.00) Locale/en',
                'x-emb-id': randomEmbedId,
                # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Forwarded-For': randomIp,
            }
            data = {
                'user[region]': 'US',
                'user[password]': 'Abcd1234!!!',
                'user[login]': email
            }
            print(data)
            response = session.post('https://www.goat.com/api/v1/users/sign_in', headers=headers, data=data, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()
                userId = response["id"]
                username = response["username"]
                authToken = response["authToken"]
                print(f"Successfully logged in {email}")
                timeOut = True
            else:
                print(response.text)
                chromeClient = ["Chrome116", "Chrome117", "Chrome118", "Chrome115"]
                session = tls_client.Session(client_identifier=random.choice(chromeClient))
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
                time.sleep(random.randint(0,3))
        except Exception as e:
            print(f"Error creating user account: {e}")
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    return session, email, userId, username, authToken

def share_invite(session, authToken):
    headers = {
        'Host': 'www.goat.com',
        'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
        'Accept': 'application/json',
        'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
        'Authorization': f'Token token="{authToken}"',
        'Accept-Language': 'en-GB,en;q=0.9',
        #'x-emb-st': '1700396816373',
        'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
        #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    listChannels = [5,6,8]
    timeOut = False
    while timeOut == False:
        try:
            if len(listChannels) > 0:
                channelSelected = random.choice(listChannels)
                country = ["france", "japan", "usa"]
                sub2 = [random.choice(country), f"{random.choice(country)} Day {random.randint(1,12)}"]
                data = {"id":random.choice(sub2),"type":random.randint(1,4),"itemType":random.randint(10,15),"channelType":channelSelected}
                response = session.post('https://www.goat.com/api/v1/community_sharing/share', headers=headers, json=data, insecure_skip_verify=True)
                if response.status_code < 310:
                    print(f"Successfully share invite for channel {channelSelected} with {authToken}")
                    listChannels = []
                else:
                    print(response.text)
                    if len(proxyList) > 0:
                        session.proxies = random.choice(proxyList)
            else:
                time.sleep(1)
                timeOut = True
        except Exception as e:
            print(f"Error creating user account: {e}")
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)

def loop_referral(email, authToken):
    session = tls_client.Session(client_identifier="Chrome116")
    if len(proxyList) > 0:
        session.proxies = random.choice(proxyList)
    share_invite(session, authToken)

def randomString(length, stringSet):
    return ''.join(random.choice(stringSet) for i in range(length))

def get_drop_details(session, authToken, dropId, email):
    session.cookies.set("device_cookie", str(uuid.uuid4()))
    session.cookies.set("currency", "USD")
    session.cookies.set("__cf_bm", f"{randomString(43, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}-{int(time.time())}-0-{randomString(67, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}Tlt{int(time.time())}-0-{randomString(10, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}/n{int(time.time())}-0-{randomString(5, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}=")
    try:
        print(f"Starting task for drop {dropId}")
        try:
            ticketCount = int(get_tickets(session, authToken))
            print(f"Able to get {ticketCount} tickets for {authToken}")
        except:
            ticketCount = 0
        cardDetails = json.loads(open("goat-cards.json").read())
        cardSelected = cardDetails[email]
        billingId, billingAddressId = cardSelected["cardId"], cardSelected["shippingId"]
        timeStamp11 = str(int(time.time() * 1000))
        randomEmbedId = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
        timeOut = False
        while timeOut == False:
            try:
                listBypassReason = [{"reason": "Error checking sdk enabled - general failure", "authorisation": "4"}, {"reason":'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.', "authorisation": f'3:{uuid.uuid4()}'}]
                selectedBypassReason = random.choice(listBypassReason)
                randomIp = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                listIosVer = ["17.0.3", "17.0.1", "17.0.2", "17.0", "16.0", "16.1", "16.2", "16.3", "16.4", "15.1", "15.0", "15.2", "15.3"]
                headers = {
                    'Host': 'www.goat.com',
                    'X-PX-AUTHORIZATION': selectedBypassReason["authorisation"],
                    'Accept': 'application/json',
                    'X-PX-BYPASS-REASON': selectedBypassReason["reason"],
                    'Authorization': f'Token token="{authToken}"',
                    'Accept-Language': 'en-GB,en;q=0.9',
                    'x-emb-st': timeStamp11,
                    'User-Agent': f'GOAT/2.66.2 (iPhone; iOS {random.choice(listIosVer)}; Scale/3.00) Locale/en',
                    'x-emb-id': randomEmbedId,
                    # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Forwarded-For': randomIp,
                }
                data = {"dropIds":[dropId]}
                response = session.post('https://www.goat.com/api/v1/drops/get-user-drops', headers=headers, json=data, insecure_skip_verify=True)
                if response.status_code < 310:
                    response111 = response.json()["drops"][0]
                    timeOut = True
                else:
                    print(response.text)
                    if len(proxyList) > 0:
                        session.proxies = random.choice(proxyList)
            except Exception as e:
                print(f"Error creating user account: {e}")
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        noTicketRequired = int(response111["entryTickets"][0]["ticketCount"])
        ticketsUnlocked = response111["ticketsUnlocked"]
        if noTicketRequired <= ticketCount:
            timeOut = False
            while timeOut == False:
                try:
                    response = session.get('https://www.goat.com/api/v1/users/me', headers=headers, insecure_skip_verify=True)
                    if response.status_code < 310:
                        timeOut = True
                    else:
                        print(response.text)
                        if len(proxyList) > 0:
                            session.proxies = random.choice(proxyList)
                except Exception as e:
                    print(f"Error creating user account: {e}")
                    if len(proxyList) > 0:
                        session.proxies = random.choice(proxyList)
            if ticketsUnlocked == False:
                session, productId, priceCents = unlocking_drop(session, authToken, dropId)
            timeOut = False
            while timeOut == False:
                try:
                    data = {"dropIds":[dropId]}
                    response = session.post('https://www.goat.com/api/v1/drops/get-user-drops', headers=headers, json=data, insecure_skip_verify=True)
                    if response.status_code < 310:
                        response111 = response.json()["drops"][0]
                        if "captchaAssets" in str(response111):
                            timeOut = True
                        else:
                            startTime = response111["startTime"] # 2023-11-19T15:30:00Z
                            startTimeStamp = int(datetime.datetime.strptime(startTime, "%Y-%m-%dT%H:%M:%SZ").timestamp())-18000
                            while startTimeStamp-1 >= int(time.time()):
                                print(f"Waiting for drop {dropId} to start at {startTime}, {startTimeStamp-int(time.time())}s left!")
                                time.sleep(random.randint(0,1))
                            if len(proxyList) > 0:
                                session.proxies = random.choice(proxyList)
                    else:
                        print(response.text)
                        if len(proxyList) > 0:
                            session.proxies = random.choice(proxyList)
                except Exception as e:
                    print(f"Error creating user account: {e}")
                    if len(proxyList) > 0:
                        session.proxies = random.choice(proxyList)
            if True:
                if True:
                    listSizes = []
                    for each in response111["sizeStockStatuses"]:
                        try:
                            if each["inStock"] == True:
                                listSizes.append(each["size"])
                        except:
                            pass
                    
                    if len(listSizes) > 0:
                        captchaAssets = response111["captchaAssets"]
                        captchaSolveId = None
                        captchaSolveId = captchaAssets[0]["id"]
                        
                        data = {"dropId":dropId,"captchaAssetId":captchaSolveId}
                        timeOut = False
                        while timeOut == False:
                            try:
                                headers = {
                                    'Host': 'www.goat.com',
                                    'X-PX-AUTHORIZATION': selectedBypassReason["authorisation"],
                                    'Accept': 'application/json',
                                    'X-PX-BYPASS-REASON': selectedBypassReason["reason"],
                                    'Authorization': f'Token token="{authToken}"',
                                    'Accept-Language': 'en-GB,en;q=0.9',
                                    'x-emb-st': timeStamp11,
                                    'User-Agent': f'GOAT/2.66.2 (iPhone; iOS {random.choice(listIosVer)}; Scale/3.00) Locale/en',
                                    'x-emb-id': randomEmbedId,
                                    # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'X-Forwarded-For': randomIp,
                                }
                                response = session.post('https://www.goat.com/api/v1/drops/submit-drop-captcha', headers=headers, json=data, insecure_skip_verify=True)
                                if response.status_code < 310:
                                    response = response.json()
                                    timeOut = True
                                else:
                                    print(response.text, response, "111", response.headers)
                                    if len(proxyList) > 0:
                                        session.proxies = random.choice(proxyList)
                            except Exception as e:
                                print(f"Error creating user account: {e}")
                                if len(proxyList) > 0:
                                    session.proxies = random.choice(proxyList)

                        #print(f"Getting product slug {dropId}")
                        
                        productTemplateSlug = response["data"]["productTemplateSlug"]
                        try:
                            #billingId, billingAddressId, cardName = getBilling(session, authToken)
                            if True:#billingId != None:
                                data = {
                                    "productTemplateSlug": productTemplateSlug,
                                    "size": str(random.choice(listSizes)),
                                    "addressId": str(billingAddressId),
                                    "billingInfoId": str(billingId)
                                }
                                timeOut = False
                                while timeOut == False:
                                    try:
                                        headers = {
                                            'Host': 'www.goat.com',
                                            'X-PX-AUTHORIZATION': selectedBypassReason["authorisation"],
                                            'Accept': 'application/json',
                                            'X-PX-BYPASS-REASON': selectedBypassReason["reason"],
                                            'Authorization': f'Token token="{authToken}"',
                                            'Accept-Language': 'en-GB,en;q=0.9',
                                            'x-emb-st': timeStamp11,
                                            'User-Agent': f'GOAT/2.66.2 (iPhone; iOS {random.choice(listIosVer)}; Scale/3.00) Locale/en',
                                            'x-emb-id': randomEmbedId,
                                            # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
                                            'Content-Type': 'application/x-www-form-urlencoded',
                                            'X-Forwarded-For': randomIp,
                                        }
                                        response = session.post(
                                            'https://www.goat.com/api/v1/order-reservation/build-reservation',
                                            headers=headers,
                                            json=data,
                                            insecure_skip_verify=True
                                        )
                                        if response.status_code < 310:
                                            response = response.json()
                                            timeOut = True
                                        else:
                                            print(response.text)
                                            if len(proxyList) > 0:
                                                session.proxies = random.choice(proxyList)
                                    except Exception as e:
                                        print(f"Error creating user account: {e}")
                                        if len(proxyList) > 0:
                                            session.proxies = random.choice(proxyList)
                                reservationId = response["reservationId"]
                                data = {"reservationId": reservationId}
                                print(session.cookies.get_dict())
                                timeOut = False
                                while timeOut == False:
                                    try:
                                        headers = {
                                            'Host': 'www.goat.com',
                                            'X-PX-AUTHORIZATION': selectedBypassReason["authorisation"],
                                            'Accept': 'application/json',
                                            'X-PX-BYPASS-REASON': selectedBypassReason["reason"],
                                            'Authorization': f'Token token="{authToken}"',
                                            'Accept-Language': 'en-GB,en;q=0.9',
                                            'x-emb-st': timeStamp11,
                                            'User-Agent': f'GOAT/2.66.2 (iPhone; iOS {random.choice(listIosVer)}; Scale/3.00) Locale/en',
                                            'x-emb-id': randomEmbedId,
                                            # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
                                            'Content-Type': 'application/x-www-form-urlencoded',
                                            'X-Forwarded-For': randomIp,
                                        }
                                        response = session.post(
                                            'https://www.goat.com/api/v1/order-reservation/submit-reservation',
                                            headers=headers,
                                            json=data,
                                            insecure_skip_verify=True
                                        )
                                        if response.status_code < 310:
                                            response = response.json()
                                            timeOut = True
                                        else:
                                            print(response.text)
                                            if len(proxyList) > 0:
                                                session.proxies = random.choice(proxyList)
                                    except Exception as e:
                                        print(f"Error creating user account: {e}")
                                        if len(proxyList) > 0:
                                            session.proxies = random.choice(proxyList)
                                print(response, time.time())
                                time.sleep(10)
                                print(f"Checkout successfully for {dropId}")
                                data = {"reservationId": reservationId}
                                timeOut = False
                                while timeOut == False:
                                    try:
                                        response = session.post(
                                            'https://www.goat.com/api/v1/order-reservation/get-reservation-status',
                                            headers=headers,
                                            json=data,
                                            insecure_skip_verify=True
                                        )
                                        if response.status_code < 310:
                                            response = response.json()
                                            if response["status"] != "ENQUEUED":
                                                print(response)
                                                timeOut = True
                                            else:
                                                print("Waiting for order to be processed!")
                                                time.sleep(5)
                                                if len(proxyList) > 0:
                                                    session.proxies = random.choice(proxyList)
                                        else:
                                            print(response.text)
                                            if len(proxyList) > 0:
                                                session.proxies = random.choice(proxyList)
                                    except Exception as e:
                                        print(f"Error creating user account: {e}")
                                        time.sleep(5)
                                        if len(proxyList) > 0:
                                            session.proxies = random.choice(proxyList)
                                time.sleep(5000)
                            else:
                                print("No billing found!")
                        except Exception as e:
                            print("Error here", e)
                            pass
                    else:
                        print("No stock available")
            time.sleep(5000)
        else:
            print("Not enough tickets!")
    except Exception as e:
        print(e)
        pass
        time.sleep(5000) 

def add_card(session, authToken, email, address, city, zipCode, state, cardNumber, cardMonth, cardYear, cardCvv):
    headers = {
        'Host': 'www.goat.com',
        'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
        'Accept': 'application/json',
        'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
        'Authorization': f'Token token="{authToken}"',
        'Accept-Language': 'en-GB,en;q=0.9',
        #'x-emb-st': '1700396816373',
        'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
        #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    codes = ['907', '205' , '251', '256', '334', '479', '501', '870', '480', '520', '602', '623', '928', '209', '310', '323', '408', '415', '510', 
            '530', '559', '562', '619', '626', '650', '661', '707', '714', '760', '805', '818', '831', '858', '909', '916', '925', '949', '951', '213',
            '303', '719', '970', '203', '860', '239', '305', '321', '352', '386', '407', '561', '727', '772', '813', '850', '863', '904', '941', '954', 
            '229', '404', '478', '706', '770', '912', '202', '302', '319', '515', '563', '641', '712', '808', '208', '217', '309', '312', '618', '630', '708', '773', '815', '847', 
            '219', '260', '317', '574', '765', '812', '316', '620', '785', '913', '270', '502', '606', '859', '225', '318', '337', '504', '985', '413', '508', '617', '781', '978', '231', '248', '269', '313', 
            '517', '586', '616', '734', '810', '906', '989', '301', '410', '207', '218', '320', '507', '612', '651', '763', '952', '314', '417', '573', '636', '660', '816', '228', '601', '662', '406', 
            '252', '336', '704', '828', '910', '919', '701', '308', '402', '603', '201', '609', '732', '856', '908', '973', '505', '575', '702', '775', '212', '315', '516', '518', '585', '607', '631', '716', '718', '845', '914', 
            '216', '330', '419', '440', '513', '614', '740', '937', '405', '580', '918', '503', '541', '215', '412', '570', '610', '717', '724', '814', '401', '210', '214', '254', '281', '325', '361', '409', '432', '512', '713', 
            '806', '817', '830', '903', '915', '936', '940', '956', '972', '979', '803', '843', '864', '605', '423', '615', '731', '865', '901', '931', '435', '801', '276', '434', '540', '703', '757', '804', '802', 
            '206', '253', '360', '425', '509', '262', '414', '608', '715', '920', '304', '307']
    phone = f"{random.choice(codes)}{str(random.randint(0,9999999)).zfill(7)}"
    firstName = names.get_first_name()
    lastName = names.get_last_name()
    data = {
        'address[addressType]': 'billing',
        'address[countryCode]': 'US',
        'address[phone]': phone,
        'address[city]': city,
        'address[state]': state,
        'address[postalCode]': zipCode,
        'address[address1]': f"{address} {random.randint(1,100)}",
        'address[id]': '-1',
        'address[address2]': '',
        'address[name]': f'{firstName} {lastName}',
    }
    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://www.goat.com/api/v1/addresses', headers=headers, data=data, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()
                timeOut = True
            else:
                print(response.text)
                time.sleep(random.randint(10,15))
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except Exception as e:
            print(f"Error creating user account: {e}")
            time.sleep(random.randint(20,50))
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    billingId  = response["id"]
    print(f"Successfully added billing address for {email}")
    data = {
        'address[addressType]': 'shipping',
        'address[address1]': f"{address} {random.randint(1,100)}",
        'address[city]': city,
        'address[address2]': '',
        'address[phone]': phone,
        'address[postalCode]': zipCode,
        'address[countryCode]': 'US',
        'address[state]': state,
        'address[name]': f'{firstName} {lastName}',
        'address[id]': '-1',
    }
    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://www.goat.com/api/v1/addresses', headers=headers, data=data, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()
                timeOut = True
            else:
                print(response.text)
                time.sleep(random.randint(10,15))
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except Exception as e:
            print(f"Error creating user account: {e}")
            time.sleep(random.randint(20,50))
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    shippingId  = response["id"]
    print(f"Successfully added shipping address for {email}")
    headers1 = {
        'Host': 'api.stripe.com',
        'Accept': '*/*',
        'Authorization': 'Bearer pk_live_eVTnJ0YFSiOvBUVnyhbC0Jfg',
        'Accept-Language': 'en-GB,en;q=0.9',
        'x-emb-st': '1700414241356',
        'Stripe-Version': '2020-08-27',
        'User-Agent': 'GOAT/1 CFNetwork/1474 Darwin/23.0.0',
        'X-Stripe-User-Agent': '{"type":"iPhone16,2","os_version":"17.0.3","lang":"objective-c","vendor_identifier":"3430D31E-F783-4E67-A5DB-B950695E863C","bindings_version":"22.8.1","model":"iPhone"}',
        'x-emb-id': 'AC3CF855DF1A489F8F439B7850814A15',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    # Formatting cardNumber to 4570 7901 7540 5867
    cardNumberFormatted = cardNumber[0:4] + " " + cardNumber[4:8] + " " + cardNumber[8:12] + " " + cardNumber[12:16]
    data = {
        'card[address_city]': city,
        'card[address_country]': 'US',
        'card[address_line1]': f"{address} {random.randint(1,100)}",
        'card[address_line2]': '',
        'card[address_zip]': zipCode,
        'card[cvc]': cardCvv,
        'card[exp_month]': str(int(cardMonth)),
        'card[exp_year]': str(cardYear),
        'card[name]': f'{firstName} {lastName}',
        'card[number]': cardNumberFormatted,
        'guid': str(uuid.uuid4()),
        'muid': str(uuid.uuid4()),
        'payment_user_agent': 'stripe-ios/22.8.1; variant.legacy',   
    }
    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://api.stripe.com/v1/tokens', headers=headers1, data=data)
            if response.status_code < 310:
                response = response.json()
                timeOut = True
            else:
                print(response.text)
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except Exception as e:
            print(f"Error creating user account: {e}")
            time.sleep(random.randint(20,50))
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    cardToken = response["id"]
    print(f"Successfully added card for {email}")
    data = {
        'billingInfo[name]': f'{firstName} {lastName}',
        'billingInfo[billingAddressId]': billingId,
        'billingInfo[processorName]': 'stripe',
        'billingInfo[stripeToken]': cardToken,
        'billingInfo[paymentType]': 'card',
    }
    timeOut = False
    while timeOut == False:
        try:
            response = session.post('https://www.goat.com/api/v1/billing_infos', headers=headers, data=data, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()
                timeOut = True
            else:
                print(response.text)
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
                time.sleep(random.randint(10,15))
        except Exception as e:
            print(f"Error creating user account: {e}")
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    cardId = response["id"]
    print(f"Successfully added billing info for {email}")
    time.sleep(random.randint(0,10))
    try:
        writeDataToJsonPreload({email: {"cardId": cardId, "cardToken": cardToken, "shippingId": shippingId, "billingId": billingId}})
    except Exception as e:
        print(e)
        pass

    with open("goat-cards.txt", "a+") as f:
        f.write(f"{email}:Abcd1234!!!:{cardId}:{cardToken}:{shippingId}:{billingId}:{authToken}\n")
        f.close()
    return cardId, cardToken, shippingId, billingId

def change_address(email, password, userId, username, authToken, cardId, cardToken, shippingId, billingId):
    try:
        session = tls_client.Session(client_identifier="Chrome116")
        if len(proxyList) > 0:
            session.proxies = random.choice(proxyList)
        address = "10 Downing Street"
        city = "Everett"
        zipCode = "01248"
        state = "New Hampshire"
        codes = ['907', '205' , '251', '256', '334', '479', '501', '870', '480', '520', '602', '623', '928', '209', '310', '323', '408', '415', '510', 
            '530', '559', '562', '619', '626', '650', '661', '707', '714', '760', '805', '818', '831', '858', '909', '916', '925', '949', '951', '213',
            '303', '719', '970', '203', '860', '239', '305', '321', '352', '386', '407', '561', '727', '772', '813', '850', '863', '904', '941', '954', 
            '229', '404', '478', '706', '770', '912', '202', '302', '319', '515', '563', '641', '712', '808', '208', '217', '309', '312', '618', '630', '708', '773', '815', '847', 
            '219', '260', '317', '574', '765', '812', '316', '620', '785', '913', '270', '502', '606', '859', '225', '318', '337', '504', '985', '413', '508', '617', '781', '978', '231', '248', '269', '313', 
            '517', '586', '616', '734', '810', '906', '989', '301', '410', '207', '218', '320', '507', '612', '651', '763', '952', '314', '417', '573', '636', '660', '816', '228', '601', '662', '406', 
            '252', '336', '704', '828', '910', '919', '701', '308', '402', '603', '201', '609', '732', '856', '908', '973', '505', '575', '702', '775', '212', '315', '516', '518', '585', '607', '631', '716', '718', '845', '914', 
            '216', '330', '419', '440', '513', '614', '740', '937', '405', '580', '918', '503', '541', '215', '412', '570', '610', '717', '724', '814', '401', '210', '214', '254', '281', '325', '361', '409', '432', '512', '713', 
            '806', '817', '830', '903', '915', '936', '940', '956', '972', '979', '803', '843', '864', '605', '423', '615', '731', '865', '901', '931', '435', '801', '276', '434', '540', '703', '757', '804', '802', 
            '206', '253', '360', '425', '509', '262', '414', '608', '715', '920', '304', '307']
        phone = f"{random.choice(codes)}{str(random.randint(0,9999999)).zfill(7)}"
        headers = {
            'Host': 'www.goat.com',
            'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
            'Accept': 'application/json',
            'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
            'Authorization': f'Token token="{authToken}"',
            'Accept-Language': 'en-GB,en;q=0.9',
            #'x-emb-st': '1700396816373',
            'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
            #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
            # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        firstName = names.get_first_name()
        lastName = names.get_last_name()

        print(f"Successfully added billing address for {email}")
        j1g = ''.join(random.choice('0123456789ABCDEF') for i in range(3))
        j1g2 = ''.join(random.choice('0123456789ABCDEF') for i in range(3))
        ad2list = ["Flat", "Apt", "Suite", "Unit", "Floor"]
        data = {
            'address[addressType]': 'shipping',
            'address[address1]': f"{address} {j1g}",
            'address[city]': city,
            'address[address2]': f"{random.choice(ad2list)} {random.randint(1,100)} {j1g2}",
            'address[phone]': phone,
            'address[postalCode]': zipCode,
            'address[countryCode]': 'US',
            'address[state]': state,
            'address[name]': f'{firstName} {lastName}',
            'address[id]': '-1',
        }
        timeOut = False
        while timeOut == False:
            try:
                response = session.post('https://www.goat.com/api/v1/addresses', headers=headers, data=data, insecure_skip_verify=True)
                if response.status_code < 310:
                    response = response.json()
                    timeOut = True
                else:
                    print(response.text)
                    time.sleep(random.randint(10,15))
                    if len(proxyList) > 0:
                        session.proxies = random.choice(proxyList)
            except Exception as e:
                print(f"Error creating user account: {e}")
                time.sleep(random.randint(20,50))
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        shippingId  = response["id"]
        print(f"Successfully added shipping address for {email}")

        try:
            writeDataToJsonPreload({email: {"cardId": cardId, "cardToken": cardToken, "shippingId": shippingId, "billingId": billingId}})
        except Exception as e:
            print(e)
            pass

        with open("goat-cards.txt", "a+") as f:
            f.write(f"{email}:Abcd1234!!!:{cardId}:{cardToken}:{shippingId}:{billingId}:{authToken}\n")
            f.close()
        return True
    except:
        pass

def writeDataToJsonPreload(new_data):
    with open("goat-cards.json", "r") as file:
        existing_data = json.load(file)

    # Update dict with new data
    existing_data.update(new_data)

    with open("goat-cards.json", "w") as file:
        jsonData = json.dumps(existing_data, indent=4)
        file.write(jsonData)

def getBilling(session, authToken):
    headers = {
        'Host': 'www.goat.com',
        'X-PX-AUTHORIZATION': f'3:{uuid.uuid4()}',
        'Accept': 'application/json',
        'X-PX-BYPASS-REASON': 'The%20certificate%20for%20this%20server%20is%20invalid.%20You%20might%20be%20connecting%20to%20a%20server%20that%20is%20pretending%20to%20be%20%E2%80%9Cpx-conf.perimeterx.net%E2%80%9D%20which%20could%20put%20your%20confidential%20information%20at%20risk.',
        'Authorization': f'Token token="{authToken}"',
        'Accept-Language': 'en-GB,en;q=0.9',
        #'x-emb-st': '1700396816373',
        'User-Agent': 'GOAT/2.66.2 (iPhone; iOS 17.0.3; Scale/3.00) Locale/en',
        #'x-emb-id': 'FFBCC9EDDE484622904A1D71E285EBCB',
        # 'Cookie': '_sneakers_session=aXQ%2F6gFhBtuAKC7kaPsT%2Fkih8Mx42C5JTO9pGU26U4o7ZzIrLXT3Wf3JNSvz3XDNTzpgk8ZVzdihMx6lMDx7Idc5VF0IfI%2BV%2FQm3XZf07E92eZqKM8WO8gjxdfTyrsLRtyGGne1RIojhIJm2UutvKydLDqK2Ds3dnPvcwle3KXQ%2F2t4DoS5xsQH76%2BpbyFZ6XljwHJy8y3SJjGx8PddLpgz5WYSDOph0wkxNcLfS5frSOPr%2BTc2hmDZhNWZjKGIbjolDxYbwtqwbU5023AGNz9v4U5IMY%2Bm9JR5iQxF64T0Hyem2NVsuoh1NTF4%2FSUOmU%2FVE8GbnTyo3WMqVOXR6JaoMo49FoB9BBmPD8D%2FScO6XZI6sf0ahL5qofDJ%2FY4LCYpIZpUPqXNlISwOlVrj34No%3D--fCmUcTshI2efHNlF--mFJeevmVlPCDNXgpNS20Hw%3D%3D; __cf_bm=JKM4XK47IkACXed5BIomF85XkKlpNNUwCdID.t0afH0-1700396814-0-AV+D/xu2bxOmBN/sYxvw5YaHxWkkSeDJ2ONSZd1vyfMfaQ9A0M04j5wrn95SutJEpsLTC9GfyIDLIJt9NwQCtPw=; currency=GBP; device_cookie=b51b3520-259e-4bea-a316-630526705794',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    timeOut = False
    while timeOut == False:
        try:
            response = session.get('https://www.goat.com/api/v1/billing_infos', headers=headers, insecure_skip_verify=True)
            if response.status_code < 310:
                response = response.json()["billingInfos"]
                timeOut = True
            else:
                print(response.text)
                if len(proxyList) > 0:
                    session.proxies = random.choice(proxyList)
        except Exception as e:
            print(f"Error creating user account: {e}")
            if len(proxyList) > 0:
                session.proxies = random.choice(proxyList)
    
    if len(response) > 0:
        billingId = response[0]["id"]
        billingAddressId = response[0]["billingAddressId"]
        name = response[0]["name"]
        return billingId, billingAddressId, name
    else:
        return None, None, None

def loop_referral111(email, email1):
    loop_referral(email, email1)

def gen_account(dummy1, dummy2):
    try:
        address, address2, city, zipCode, state = getAddress()
        cardNumber, cardMonth, cardYear, cardCvv, zip = random.choice(listCards).split(":")
        #loop_referral(email)
        session = tls_client.Session(client_identifier="Chrome116")
        if len(proxyList) > 0:
            session.proxies = random.choice(proxyList)
        session, email, userId, username, authToken = generate_account(session)#login(session, email)
        print(f"Successfully created account for {email}")
        add_card(session, authToken, email, address, city, zipCode, state, cardNumber, cardMonth, cardYear, cardCvv)
        print(f"Successfully added card for {email}")
        onboarding(session, authToken)
        print(f"Successfully onboarded account for {email}")
        loop_referral(session, authToken)
        print(f"Successfully shared referral for {email}")
        with open("goat-accounts.txt", "a+") as f:
            f.write(f"{email}:Abcd1234!!!:{userId}:{username}:{authToken}\n")
            f.close()
    except:
        pass

listCards = """card:month:year:cvv:billingZip"""

def multi_run_wrapper(args):
    return get_drop_details(*args)

with open("goat-accounts.txt", "r") as f:
    listAccounts = f.read()
    listAccounts = listAccounts.splitlines()

dropId = str(input("Enter drop id (e.g 6e240c5e-9801-4025-9167-9b1740edc214): "))

listCards = listCards.splitlines()

profilesToRun = []
for each in listAccounts:
    session = tls_client.Session(client_identifier="Chrome116")
    if len(proxyList) > 0:
        session.proxies = random.choice(proxyList)
    email, password, userId, username, authToken = each.split(":")
    profilesToRun.append((session, authToken, dropId, email))

random.shuffle(profilesToRun)
profilesToRun = profilesToRun[0:500]

while True:
    try:
        pool = ThreadPool(100)
        result = pool.map(multi_run_wrapper, profilesToRun)
        pool.close()
        pool.join()
        time.sleep(5000)
    except Exception as e:
        print(e)
        pass