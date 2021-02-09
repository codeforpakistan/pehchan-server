import json


def test_add_user(test_app, test_database):
    client = test_app.test_client()
    resp = client.post(
        '/users',
        data=json.dumps({
            'username': 'john',
            'email': 'john@test.com'
        }), 
        content_type='application/json'
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 201
    assert 'john@test.com was added!' in data['message']


def test_invalid_json_request(test_app, test_database):
    client = test_app.test_client()
    resp = client.post(
        'users',
        data=json.dumps({}),
        content_type='application/json'
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 400
    assert 'Input payload validation failed' in data['message']


def test_user_already_exists(test_app, test_database):
    client = test_app.test_client()
    resp = client.post(
        'users',
        data=json.dumps({
            'username': 'john',
            'email': 'john@test.com'
        }),
        content_type='application/json'
    )