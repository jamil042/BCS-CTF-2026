# Reach Forums - Simple Write-up

## 1. The start
Police found a public notice page at `http://172.16.38.22:8888`.
It said the old hidden site was closed and gave a new hidden address ending in `.onion`.

## 2. Going hidden
Normal internet cannot open `.onion` names.
We used Tor, a private connection running on this computer at `127.0.0.1:9050`.
This let us open:
`http://scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion`

That site was Reach Forums. It asked for login. To register you needed a 4-digit invite code.

## 3. The door code
We tried all codes from 0000 to 9999.
Only `0777` worked.
We made an account and logged in.

## 4. The missing post
One selling post by `magstripe` said:
`This post has been taken down due to potential policy violations.`

Replies under it said he posted proof badly and people could guess secrets from it.
That proof likely had the admin home address.

The forum also said it uses an automatic checker that hides staff posts if they leak private info.

## 5. The number trick
Each discussion has a number, like `/thread/5`.
The site took that number and asked its notebook for that page, without checking it safely.

We asked for strange numbers like:
`5 AND 1=1` and `5 AND 1=2`
One gave a page, one gave empty. That proved we could ask clever questions.

Then we asked it to mix in other pages from its notebook.
We learned its notebook has these boxes:
`users, threads, posts, removed_posts`

`removed_posts` is the trash box where hidden posts go. There was only 1 hidden post in it.

We asked for that hidden post. It gave us magstripe's original text.
That text had a picture link:
`/images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png`

## 6. The picture
We opened that picture. It is saved here as `magstripe_proof.png`.
It is a screenshot of a fake shop order.

It shows:
```
Billing name: John
Shipping address: 3c, Kalindi Tower, Dhaka, Bangladesh
```

This is the mistake the forum warned about: he used his real address as fake test data in the screenshot.

User `magstripe` is user number 3, an admin/staff seller.

## 7. The flag
The challenge wants only the address, with no commas, and _ instead of spaces.

From:
`3c, Kalindi Tower, Dhaka, Bangladesh`

To:
`3c_Kalindi_Tower_Dhaka_Bangladesh`

Final answer:
`bcsctf{3c_Kalindi_Tower_Dhaka_Bangladesh}`
