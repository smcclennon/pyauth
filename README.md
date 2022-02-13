# pyauth
My first experience playing with credential storage and salting.

This program has basic persistence where hashed and salted credentials are stored within a [json file](user_db.json) in this structure:
```json
{
  "smcclennon": {
    "salt": "rv9GxrD+t7FXVX56HujEwv4u3PotI/mATbIu/gYki3k=",
    "key": "2GIYu7hM4LzjceYaGDG7kCUgQqiOhNu4esmZFk3cdfA=",
    "example_data": 0
  }
}

```
In the example above, the user is `smcclennon`, whose password is `.github.io`.

Screenshots using the database shown above:

![Authentication success](https://user-images.githubusercontent.com/24913281/153735336-1fe64da0-9f52-4892-b257-88f9342a9b04.png)
![Authentication failure](https://user-images.githubusercontent.com/24913281/153735342-4336a8c4-4f03-41b7-a98e-89ee715240b6.png)

Window manager in the screenshots is [Byobu](https://www.byobu.org/)
