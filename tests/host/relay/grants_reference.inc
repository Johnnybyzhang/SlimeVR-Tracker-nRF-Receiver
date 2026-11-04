/* One PING/PONG in R0-R1 for the member waiting longest past min_age, if
 * no repair holds them. Rotation breaks ties. */
static void reference_maintenance(struct relay_coord *rc, struct relay_control *c, uint32_t now_ms,
	uint32_t min_age)
{
	if (c->grants[0].owner != RELAY_OWNER_IDLE || c->grants[1].owner != RELAY_OWNER_IDLE) {
		return;
	}
	int owner = -1;
	uint32_t oldest = 0;
	for (unsigned n = 0; n < RC_MAX; n++) {
		uint8_t id = (rc->maintenance_next + n) % RC_MAX;
		uint32_t age = now_ms - rc->maintenance_ms[id];
		if ((c->members & RC_BIT(id)) && age >= min_age && (owner < 0 || age > oldest)) {
			owner = id;
			oldest = age;
		}
	}
	if (owner < 0) {
		return;
	}
	c->maintenance_owner = owner;
	c->flags |= RELAY_CONTROL_MAINTENANCE;
	c->grants[0] = c->grants[1] = (struct relay_grant){.owner = RELAY_OWNER_MAINTENANCE};
	rc->maintenance_ms[owner] = now_ms;
	rc->maintenance_next = (owner + 1U) % RC_MAX;
}

void reference_build_grants(struct relay_coord *rc, struct relay_control *c, uint32_t now_ms, const struct rc_grant_plan *plan)
{
	for (unsigned i = 0; i < c->repair_count; i++) {
		c->grants[i] = (struct relay_grant){.owner = RELAY_OWNER_IDLE};
	}
	c->maintenance_owner = RELAY_OWNER_IDLE;
	c->flags &= ~RELAY_CONTROL_MAINTENANCE;
	/* Commands and layouts must reach a member even when repairs fill every frame. */
	reference_maintenance(rc, c, now_ms, RC_MAINTENANCE_URGENT_MS);
	uint8_t count[RELAY_V3_REPAIR_SLOTS] = {0};
	/* Oldest deadline first; group children sharing a helper into its grant. */
	for (unsigned copy = 0; copy < 2; copy++) {
		for (int age = RELAY_V3_CACHE_FRAMES - 1; age >= 0; age--) {
			uint32_t frame = c->frame - age;
			struct rc_watch *w = &rc->watch[frame % RELAY_V3_CACHE_FRAMES];
			if (w->frame != frame) {
				continue;
			}
			struct rc_receipt *r = &rc->receipt[frame % RELAY_V3_CACHE_FRAMES];
			if (r->frame == frame) {
				c->missing[age] &= ~r->received;
			}
			uint16_t missing = c->missing[age] & (copy ? w->backup_valid : w->primary_valid);
			for (uint8_t child = 0; child < RC_MAX; child++) {
				if (!(missing & (1U << child))) {
					continue;
				}
				uint8_t helper = (w->helpers[child] >> (copy * 4U)) & 15U;
				unsigned slot, idle = c->repair_count;
				for (slot = 0; slot < c->repair_count; slot++) {
					if (c->grants[slot].owner == helper && count[slot] < RELAY_MAX_CHILDREN) {
						break;
					}
					if (idle == c->repair_count && c->grants[slot].owner == RELAY_OWNER_IDLE) {
						idle = slot;
					}
				}
				if (slot == c->repair_count) {
					if (idle == c->repair_count) {
						continue;
					}
					slot = idle;
					c->grants[slot].owner = helper;
				}
				c->grants[slot].children |= 1U << child;
				count[slot]++;
			}
		}
	}
	reference_maintenance(rc, c, now_ms, RC_MAINTENANCE_MS);
	c->survey = 0;
	if (c->frame % 10U == 0) {
		for (unsigned n = 0; n < RC_MAX; n++) {
			uint8_t child = (rc->survey_next + n) % RC_MAX;
			if (c->members & RC_BIT(child)) {
				c->survey |= RC_BIT(child);
				rc->survey_next = (child + 1U) % RC_MAX;
				break;
			}
		}
	} else {
		int best = -1;
		for (unsigned offset = 0; offset < RC_MAX; offset++) {
			unsigned child = (rc->survey_next + offset) % RC_MAX;
			if (!(c->members & RC_BIT(child)) || !rc->t[child].direct_permille ||
			    rc->t[child].direct_permille >= RC_HEAD_MIN_PERMILLE) continue;
			if (best < 0 || rc->t[child].direct_permille < rc->t[best].direct_permille)
				best = child;
		}
		if (best >= 0) c->survey = RC_BIT(best);
	}
	uint16_t failed = c->missing[0] & plan->fresh_survey;
	for (unsigned age = 1; age < RELAY_V3_CACHE_FRAMES; age++) {
		failed |= c->missing[age];
	}
	for (uint8_t child = 0; child < RC_MAX && relay_mask_count(c->survey) < 2; child++) {
		if (failed & c->members & RC_BIT(child)) c->survey |= RC_BIT(child);
	}
	/* Reports use only capacity left after repairs and maintenance. */
	int reporter = -1;
	uint32_t oldest = 0;
	for (unsigned n = 0; n < RC_MAX; n++) {
		uint8_t h = (rc->report_next + n) % RC_MAX;
		uint32_t age = now_ms - rc->report_ms[h];
		if ((c->members & RC_BIT(h)) && age >= 1000U && (reporter < 0 || age > oldest)) {
			reporter = h;
			oldest = age;
		}
	}
	for (unsigned slot = 0; reporter >= 0 && slot < c->repair_count; slot++) {
		if (c->grants[slot].owner == RELAY_OWNER_IDLE) {
			c->grants[slot].owner = reporter;
			rc->report_ms[reporter] = now_ms;
			rc->report_next = (reporter + 1U) % RC_MAX;
			break;
		}
	}
	/* A planned survey copy has priority over the spare retry only. */
	bool rescued = false;
	if (c->missing[plan->rescue_age] & plan->rescue_child) {
		for (unsigned slot = 0; slot < c->repair_count; slot++) {
			if (c->grants[slot].owner == RELAY_OWNER_IDLE) {
				c->grants[slot] = (struct relay_grant){plan->rescue_helper, plan->rescue_child};
				rescued = true;
				if (plan->rescue_second < RC_MAX) {
					for (unsigned extra = slot + 1; extra < c->repair_count; extra++) {
						if (c->grants[extra].owner != RELAY_OWNER_IDLE) continue;
						c->grants[extra] = (struct relay_grant){plan->rescue_second, plan->rescue_child};
						break;
					}
				}
				break;
			}
		}
	}
	/* A spare slot retries the earliest repair after all original work. */
	int retry = -1;
	for (unsigned slot = 0; !rescued && slot < c->repair_count; slot++) {
		if (retry < 0 && c->grants[slot].children) retry = slot;
		if (retry >= 0 && c->grants[slot].owner == RELAY_OWNER_IDLE) {
			c->grants[slot] = c->grants[retry];
			break;
		}
	}
	if (plan->rescue_child) {
		uint16_t reserved = 0;
		for (unsigned slot = 0; slot < c->repair_count; slot++) {
			unsigned helper = c->grants[slot].owner;
			if ((helper == plan->rescue_helper || helper == plan->rescue_second) &&
			    (c->grants[slot].children & plan->rescue_child)) reserved |= RC_BIT(helper);
		}
		unsigned frame = c->frame - plan->rescue_age;
		if (reserved && rc->watch[frame % 3].frame == frame) {
			if (rc->watch[frame % 3].rescue_child != plan->rescue_child)
				rc->watch[frame % 3].rescue_helpers = 0;
			rc->watch[frame % 3].rescue_child = plan->rescue_child;
			rc->watch[frame % 3].rescue_helpers |= reserved;
		}
	}
	struct rc_watch *next = &rc->watch[(c->frame + 1U) % RELAY_V3_CACHE_FRAMES];
	*next = (struct rc_watch){
	    .frame = c->frame + 1U, .session = c->session, .epoch = c->epoch,
	    .members = c->members, .survey = c->survey, .primary_valid = c->primary_valid, .backup_valid = c->backup_valid};
	memcpy(next->helpers, c->helpers, sizeof(next->helpers));
	for (unsigned child = 0; child < RC_MAX; child++) {
		next->listeners[child] = plan->next_listeners[child];
		if (c->survey & RC_BIT(child)) next->listeners[child] = c->members;
	}
}
