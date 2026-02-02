type User = {
	provider: string;
	provider_id: string;
	username: string;
	avatar_url: string;
	created_at: string;
};

export const userState = $state({
	user: null as User | null,
});
