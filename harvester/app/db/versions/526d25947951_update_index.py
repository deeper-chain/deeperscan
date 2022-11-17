"""update index

Revision ID: 526d25947951
Revises: 61f91ed008b9
Create Date: 2022-11-17 12:27:10.813346

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '526d25947951'
down_revision = '61f91ed008b9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('data_event_block_datetime_IDX', 'data_event', ['block_datetime'])



def downgrade():
    op.drop_index("data_event_block_datetime_IDX")

