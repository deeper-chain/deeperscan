#! /usr/bin/env sh

if [ -z $ENVIRONMENT ] || [ "$ENVIRONMENT" = "dev" ]; then
    ENVIRONMENT="dev"
fi

echo "==========================="
echo "Environment: $ENVIRONMENT"
echo "==========================="

echo "Running gunicorn..."

if [ "$ENVIRONMENT" = "dev" ]; then
    # Expand path to local versions of packages
    export PYTHONPATH=$PYTHONPATH:./py-substrate-interface/:./py-scale-codec/

    gunicorn -b 0.0.0.0:8000 --workers=1 app.main:app --reload --timeout 600
fi

if [ "$ENVIRONMENT" = "prod" ]; then
    gunicorn -b 0.0.0.0:8000 --workers=5 app.main:app --worker-class=gevent --worker-connections=1000 --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %({x-forwarded-for}i)s %(L)s' --access-logfile - --error-logfile -
fi
